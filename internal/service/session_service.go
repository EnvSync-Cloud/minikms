package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/auth"
	"github.com/envsync-cloud/minikms/internal/authn"
	"github.com/envsync-cloud/minikms/internal/pki"
	"github.com/envsync-cloud/minikms/internal/pkistore"
	"github.com/envsync-cloud/minikms/internal/store"
)

// SessionPolicyStore defines the policy/token methods SessionService needs from the store.
type SessionPolicyStore interface {
	GetOrgSecurityPolicy(ctx context.Context, orgID string) (*store.OrgSecurityPolicy, error)
	// GetTokensBySubject returns unexpired tokens for subjectHash in orgID only.
	GetTokensBySubject(ctx context.Context, orgID, subjectHash string) ([]*auth.TokenEntry, error)
	// RevokeTokensBySubject revokes unexpired tokens for subjectHash in orgID only.
	RevokeTokensBySubject(ctx context.Context, orgID, subjectHash string) (int, error)
}

// SessionService manages time-based session tokens tied to member certificates.
type SessionService struct {
	signingKey  *ecdsa.PrivateKey // Ed25519-equivalent: ECDSA P-256 for JWT signing
	issuer      string
	defaultTTL  time.Duration
	registry    auth.TokenRegistry
	certStore   pkistore.Store
	policyStore SessionPolicyStore
	auditLogger *audit.AuditLogger
	challenges  store.ChallengeStore
}

func NewSessionService(
	signingKey *ecdsa.PrivateKey,
	issuer string,
	defaultTTL time.Duration,
	registry auth.TokenRegistry,
	certStore pkistore.Store,
	policyStore SessionPolicyStore,
	auditLogger *audit.AuditLogger,
	challenges store.ChallengeStore,
) *SessionService {
	return &SessionService{
		signingKey:  signingKey,
		issuer:      issuer,
		defaultTTL:  defaultTTL,
		registry:    registry,
		certStore:   certStore,
		policyStore: policyStore,
		auditLogger: auditLogger,
		challenges:  challenges,
	}
}

type IssueSessionChallengeResponse struct {
	Nonce     []byte
	ExpiresAt time.Time
}

func (s *SessionService) IssueSessionChallenge(ctx context.Context, certSerial string) (*IssueSessionChallengeResponse, error) {
	if certSerial == "" {
		return nil, invalidArgument("cert_serial is required")
	}
	certRecord, err := s.certStore.GetCertificateBySerial(ctx, certSerial)
	if err != nil {
		return nil, internalError("failed to check certificate status", err)
	}
	if certRecord == nil || certRecord.Status != "active" {
		return nil, NewDomainError(ErrorUnauthenticated, "certificate authentication failed",
			fmt.Errorf("certificate not found or not active"))
	}
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	if err := s.challenges.Put(ctx, nonce, certSerial, store.SessionChallengeTTL); err != nil {
		return nil, internalError("failed to store session challenge", err)
	}
	return &IssueSessionChallengeResponse{
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(store.SessionChallengeTTL),
	}, nil
}

// SessionClaims extends JWT claims with session-specific fields.
type SessionClaims struct {
	jwt.RegisteredClaims
	OrgID      string   `json:"org"`
	Role       string   `json:"role"`
	CertSerial string   `json:"cert_serial"`
	Scopes     []string `json:"scopes"`
	Kind       string   `json:"kind,omitempty"`
	AppID      string   `json:"app,omitempty"`
	EnvID      string   `json:"env,omitempty"`
}

// CreateSessionByCertRequest represents a BYOK/CLI certificate-based auth request.
type CreateSessionByCertRequest struct {
	CertPEM     string
	SignedNonce []byte
	Nonce       []byte
	Scopes      []string
}

// CreateSessionResponse represents the result of session creation.
type CreateSessionResponse struct {
	SessionToken string
	ExpiresAt    time.Time
	Scopes       []string
}

// CreateSessionByCert authenticates a member using their certificate and signed nonce.
func (s *SessionService) CreateSessionByCert(ctx context.Context, req *CreateSessionByCertRequest) (*CreateSessionResponse, error) {
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if req.CertPEM == "" {
		return nil, invalidArgument("cert_pem is required")
	}
	if len(req.Nonce) == 0 {
		return nil, invalidArgument("nonce is required")
	}
	if len(req.SignedNonce) == 0 {
		return nil, invalidArgument("signed_nonce is required")
	}

	presented, serialHex, err := parseMemberCertProof(req.CertPEM, req.Nonce, req.SignedNonce)
	if err != nil {
		return nil, err
	}

	certRecord, err := s.certStore.GetCertificateBySerial(ctx, serialHex)
	if err != nil {
		return nil, internalError("failed to check certificate status", err)
	}
	if certRecord == nil || presented.SerialNumber.Text(16) != certRecord.SerialNumber {
		return nil, certAuthFailed(fmt.Errorf("certificate not found in registry"))
	}
	// The presented PEM must be the issued certificate. A self-signed
	// certificate that only reuses the serial is not that certificate.
	if !registryPEMMatches(req.CertPEM, certRecord.CertPEM) {
		return nil, certAuthFailed(fmt.Errorf("certificate does not match registry"))
	}
	if err := s.verifyRegistryCertChainsToOrgCA(ctx, certRecord); err != nil {
		return nil, err
	}
	if certRecord.Status != "active" || !certRecord.ExpiresAt.After(time.Now()) {
		return nil, certAuthFailed(fmt.Errorf("certificate is not active"))
	}

	// Identity comes from the registry record, not from presented OIDs.
	memberID, orgID, role, err := identityFromRegistry(certRecord)
	if err != nil {
		return nil, err
	}

	boundSerial, ok, err := s.challenges.Consume(ctx, req.Nonce)
	if err != nil {
		return nil, internalError("failed to consume session challenge", err)
	}
	if !ok || boundSerial != certRecord.SerialNumber {
		return nil, certAuthFailed(fmt.Errorf("session challenge is missing, expired, or bound to a different certificate"))
	}

	// Determine scopes
	scopes := s.resolveScopes(req.Scopes, role)

	// Issue session token
	return s.issueSessionToken(ctx, memberID, orgID, role, certRecord.SerialNumber, scopes, "", "", "")
}

// parseMemberCertProof checks that the caller holds the presented certificate's
// private key. It does not read identity; OIDs in this certificate are untrusted
// until the registry PEM and CA chain have been checked.
func parseMemberCertProof(certPEM string, nonce, signedNonce []byte) (*x509.Certificate, string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, "", certAuthFailed(fmt.Errorf("invalid PEM certificate"))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", certAuthFailed(err)
	}
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", certAuthFailed(fmt.Errorf("certificate does not contain an ECDSA public key"))
	}
	hash := sha256.Sum256(nonce)
	if !ecdsa.VerifyASN1(pubKey, hash[:], signedNonce) {
		return nil, "", certAuthFailed(fmt.Errorf("nonce signature verification failed"))
	}
	if cert.SerialNumber == nil {
		return nil, "", certAuthFailed(fmt.Errorf("certificate serial is missing"))
	}
	return cert, cert.SerialNumber.Text(16), nil
}

func registryPEMMatches(presented, stored string) bool {
	if presented == "" || stored == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(stored)) == 1
}

func parseCertificatePEM(certPEM string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM certificate")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("trailing PEM data")
	}
	return x509.ParseCertificate(block.Bytes)
}

// verifyRegistryCertChainsToOrgCA checks the stored certificate against the
// org (or environment) CA named by the registry record. The presented
// certificate is not used as a trust anchor.
func (s *SessionService) verifyRegistryCertChainsToOrgCA(ctx context.Context, rec *pkistore.CertRecord) error {
	if rec == nil || rec.CertType != "member" {
		return certAuthFailed(fmt.Errorf("certificate is not a member certificate"))
	}
	cert, err := parseCertificatePEM(rec.CertPEM)
	if err != nil {
		return internalError("stored member certificate is invalid", err)
	}
	if cert.IsCA {
		return certAuthFailed(fmt.Errorf("member certificate must not be a CA"))
	}

	orgCARec, err := s.certStore.GetOrgCA(ctx, rec.OrgID, rec.EnvID)
	if err != nil {
		return internalError("failed to load organization CA", err)
	}
	if orgCARec == nil || orgCARec.Status != "active" {
		return certAuthFailed(fmt.Errorf("organization CA is not available"))
	}
	orgCert, err := parseCertificatePEM(orgCARec.CertPEM)
	if err != nil {
		return internalError("stored organization CA certificate is invalid", err)
	}
	if !orgCert.IsCA || !orgCert.BasicConstraintsValid {
		return certAuthFailed(fmt.Errorf("organization CA is not a CA"))
	}

	roots := x509.NewCertPool()
	roots.AddCert(orgCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return certAuthFailed(err)
	}
	return nil
}

// identityFromRegistry reads member, org, and role from the stored certificate
// record. Org is the registry column; member and role are extensions on the
// issued certificate kept in that record.
func identityFromRegistry(rec *pkistore.CertRecord) (string, string, string, error) {
	cert, err := parseCertificatePEM(rec.CertPEM)
	if err != nil {
		return "", "", "", internalError("stored member certificate is invalid", err)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Text(16) != rec.SerialNumber {
		return "", "", "", certAuthFailed(fmt.Errorf("registry serial does not match certificate"))
	}
	memberID := pki.ExtractOIDValue(cert, pki.OIDMemberID)
	orgID := pki.ExtractOIDValue(cert, pki.OIDOrgID)
	role := pki.ExtractOIDValue(cert, pki.OIDRole)
	if memberID == "" || role == "" || rec.OrgID == "" || orgID != rec.OrgID {
		return "", "", "", certAuthFailed(fmt.Errorf("registry identity is incomplete"))
	}
	return memberID, rec.OrgID, role, nil
}

func certAuthFailed(cause error) error {
	return NewDomainError(ErrorUnauthenticated, "certificate authentication failed", cause)
}

// ValidateSessionRequest represents a session validation request.
type ValidateSessionRequest struct {
	SessionToken string
}

// ValidateSessionResponse represents the result of session validation.
type ValidateSessionResponse struct {
	Valid      bool
	MemberID   string
	OrgID      string
	Role       string
	CertSerial string
	Scopes     []string
	ExpiresAt  time.Time
}

// ValidateSession validates a session token and returns the session info.
func (s *SessionService) ValidateSession(ctx context.Context, req *ValidateSessionRequest) (*ValidateSessionResponse, error) {
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if req.SessionToken == "" {
		return nil, invalidArgument("session_token is required")
	}

	// Parse the JWT
	claims := &SessionClaims{}
	token, err := jwt.ParseWithClaims(req.SessionToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &s.signingKey.PublicKey, nil
	})
	if err != nil {
		return &ValidateSessionResponse{Valid: false}, nil
	}
	if !token.Valid {
		return &ValidateSessionResponse{Valid: false}, nil
	}

	// Verify token exists in registry and hasn't been revoked
	jwtHash := auth.HashJWT(req.SessionToken)
	entry, err := s.registry.GetToken(ctx, claims.ID)
	if err != nil {
		return nil, internalError("failed to look up session token", err)
	}
	if entry == nil {
		return &ValidateSessionResponse{Valid: false}, nil
	}
	if entry.Revoked {
		return &ValidateSessionResponse{Valid: false}, nil
	}
	if entry.JWTHash != jwtHash {
		return &ValidateSessionResponse{Valid: false}, nil
	}

	// Session tokens are cert-session tokens. The registry serial is authoritative.
	// An empty serial, a serial that differs from the token, or a certificate
	// that is not active is rejected.
	if claims.CertSerial == "" || entry.CertSerial == "" || claims.CertSerial != entry.CertSerial {
		return &ValidateSessionResponse{Valid: false}, nil
	}
	if s.certStore == nil {
		return nil, internalError("failed to check session certificate", nil)
	}
	certRecord, err := s.certStore.GetCertificateBySerial(ctx, entry.CertSerial)
	if err != nil {
		return nil, internalError("failed to check session certificate", err)
	}
	if certRecord == nil || certRecord.Status != "active" {
		return &ValidateSessionResponse{Valid: false}, nil
	}

	return &ValidateSessionResponse{
		Valid:      true,
		MemberID:   claims.Subject,
		OrgID:      claims.OrgID,
		Role:       claims.Role,
		CertSerial: claims.CertSerial,
		Scopes:     claims.Scopes,
		ExpiresAt:  claims.ExpiresAt.Time,
	}, nil
}

// RevokeSession invalidates a session token.
func (s *SessionService) RevokeSession(ctx context.Context, sessionToken string) error {
	if sessionToken == "" {
		return invalidArgument("session_token is required")
	}

	// Parse to get JTI
	claims := &SessionClaims{}
	_, err := jwt.ParseWithClaims(sessionToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return &s.signingKey.PublicKey, nil
	})
	if err != nil {
		return NewDomainError(ErrorUnauthenticated, "invalid session token", err)
	}

	if err := s.registry.RevokeToken(ctx, claims.ID); err != nil {
		return internalError("failed to revoke session", err)
	}

	_ = s.auditLogger.Log(ctx, claims.OrgID, "session_revoked", claims.Subject,
		fmt.Sprintf("Session %s revoked", claims.ID), "")

	return nil
}

// RevokeMemberSessions invalidates all sessions for a member in the caller's org.
func (s *SessionService) RevokeMemberSessions(ctx context.Context, memberID, orgID string) (int, error) {
	principal, err := authorizeMemberSessionAccess(ctx, memberID, orgID)
	if err != nil {
		return 0, err
	}

	subjectHash := auth.HashSubject(memberID)
	count, err := s.policyStore.RevokeTokensBySubject(ctx, principal.TenantID, subjectHash)
	if err != nil {
		return 0, internalError("failed to revoke member sessions", err)
	}

	_ = s.auditLogger.Log(ctx, principal.TenantID, "member_sessions_revoked", principal.ActorID,
		fmt.Sprintf("All sessions revoked for member %s (%d sessions)", memberID, count), "")

	return count, nil
}

// ListSessionsResponse holds active sessions for a member.
type ListSessionsResponse struct {
	Sessions []SessionInfo
}

// SessionInfo describes a single session.
type SessionInfo struct {
	JTI        string
	CertSerial string
	Scopes     []string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Revoked    bool
}

// ListSessions returns active sessions for a member in the caller's org.
func (s *SessionService) ListSessions(ctx context.Context, memberID, orgID string) (*ListSessionsResponse, error) {
	principal, err := authorizeMemberSessionAccess(ctx, memberID, orgID)
	if err != nil {
		return nil, err
	}

	subjectHash := auth.HashSubject(memberID)
	entries, err := s.policyStore.GetTokensBySubject(ctx, principal.TenantID, subjectHash)
	if err != nil {
		return nil, internalError("failed to list sessions", err)
	}

	sessions := make([]SessionInfo, len(entries))
	for i, e := range entries {
		sessions[i] = SessionInfo{
			JTI:       e.JTI,
			IssuedAt:  e.IssuedAt,
			ExpiresAt: e.ExpiresAt,
			Revoked:   e.Revoked,
		}
	}

	return &ListSessionsResponse{Sessions: sessions}, nil
}

// GenerateNonce generates a cryptographically random nonce for challenge-response auth.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, internalError("failed to generate nonce", err)
	}
	return nonce, nil
}

// IssueBootstrapSession issues a session for a managed member whose private key
// stays on the server. It is not exposed as an RPC.
func (s *SessionService) IssueBootstrapSession(ctx context.Context, memberID, orgID, role, certSerial string) (string, error) {
	if memberID == "" || orgID == "" || role == "" || certSerial == "" {
		return "", invalidArgument("bootstrap session fields are required")
	}
	// Reissue replaces the previous admin session so the per-subject cap is not exhausted.
	_, _ = s.policyStore.RevokeTokensBySubject(ctx, orgID, auth.HashSubject(memberID))
	resp, err := s.issueSessionToken(ctx, memberID, orgID, role, certSerial, s.resolveScopes(nil, role), authn.KindService, "", "")
	if err != nil {
		return "", err
	}
	return resp.SessionToken, nil
}

// issueSessionToken creates and stores a JWT session token.
// IssueMachineSession mints a workload session. It cannot carry admin or PKI scopes.
func (s *SessionService) IssueMachineSession(ctx context.Context, memberID, orgID, certSerial, appID, envID string, scopes []string) (*CreateSessionResponse, error) {
	if memberID == "" || orgID == "" || certSerial == "" || appID == "" {
		return nil, invalidArgument("machine session fields are required")
	}
	var granted []string
	for _, scope := range scopes {
		switch scope {
		case "vault:read", "vault:write", "vault:delete":
			granted = append(granted, scope)
		}
	}
	if len(granted) == 0 {
		granted = []string{"vault:read"}
	}
	return s.issueSessionToken(ctx, memberID, orgID, "machine", certSerial, granted, authn.KindMachine, appID, envID)
}

func (s *SessionService) issueSessionToken(ctx context.Context, memberID, orgID, role, certSerial string, scopes []string, kind, appID, envID string) (*CreateSessionResponse, error) {
	// Check session count limit
	policy, err := s.policyStore.GetOrgSecurityPolicy(ctx, orgID)
	if err != nil {
		return nil, internalError("failed to get org security policy", err)
	}

	subjectHash := auth.HashSubject(memberID)
	existingTokens, err := s.policyStore.GetTokensBySubject(ctx, orgID, subjectHash)
	if err != nil {
		return nil, internalError("failed to check existing sessions", err)
	}

	activeCount := 0
	for _, t := range existingTokens {
		if !t.Revoked && t.ExpiresAt.After(time.Now()) {
			activeCount++
		}
	}
	if activeCount >= policy.MaxSessionTokens {
		return nil, NewDomainError(ErrorResourceExhausted, "maximum active sessions reached", nil)
	}

	// Determine TTL
	ttl := time.Duration(policy.SessionDurationSec) * time.Second
	if ttl == 0 {
		ttl = s.defaultTTL
	}

	jti := uuid.New().String()
	now := time.Now()
	expiresAt := now.Add(ttl)

	claims := SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   memberID,
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		OrgID:      orgID,
		Role:       role,
		CertSerial: certSerial,
		Scopes:     scopes,
		Kind:       kind,
		AppID:      appID,
		EnvID:      envID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, err := token.SignedString(s.signingKey)
	if err != nil {
		return nil, internalError("failed to sign session token", err)
	}

	// Store in registry
	entry := &auth.TokenEntry{
		JTI:         jti,
		SubjectHash: subjectHash,
		JWTHash:     auth.HashJWT(signedToken),
		IssuedAt:    now,
		ExpiresAt:   expiresAt,
		Revoked:     false,
		CertSerial:  certSerial,
		Scopes:      scopes,
	}
	if err := s.registry.StoreToken(ctx, entry); err != nil {
		return nil, internalError("failed to store session token", err)
	}

	_ = s.auditLogger.Log(ctx, orgID, "session_created", memberID,
		fmt.Sprintf("Session created (jti: %s, cert: %s, expires: %s)", jti, certSerial, expiresAt.Format(time.RFC3339)), "")

	return &CreateSessionResponse{
		SessionToken: signedToken,
		ExpiresAt:    expiresAt,
		Scopes:       scopes,
	}, nil
}

// resolveScopes determines the final scopes based on request and role.
func (s *SessionService) resolveScopes(requested []string, role string) []string {
	// Default scopes based on role
	defaultScopes := map[string][]string{
		"master":    {"vault:read", "vault:write", "vault:delete", "pki:issue"},
		"admin":     {"vault:read", "vault:write", "vault:delete", "pki:issue"},
		"member":    {"vault:read", "vault:write"},
		"developer": {"vault:read", "vault:write"},
		"readonly":  {"vault:read"},
		"viewer":    {"vault:read"},
	}

	defaults, ok := defaultScopes[role]
	if !ok {
		defaults = []string{"vault:read"}
	}

	if len(requested) == 0 {
		return defaults
	}

	// Filter requested scopes to only those allowed by role
	allowedSet := make(map[string]bool)
	for _, s := range defaults {
		allowedSet[s] = true
	}

	var filtered []string
	for _, s := range requested {
		if allowedSet[s] {
			filtered = append(filtered, s)
		}
	}

	if len(filtered) == 0 {
		return defaults
	}
	return filtered
}

// --- Helper to extract OID values from certs ---
// These are available via the pki package but we add a convenience here

// ValidateSessionFromMetadata extracts and validates a session token from gRPC metadata.
// Returns the validated session info or an error.
func (s *SessionService) ValidateSessionFromToken(ctx context.Context, token string) (*ValidateSessionResponse, error) {
	if token == "" {
		return nil, NewDomainError(ErrorUnauthenticated, "invalid session token", nil)
	}
	resp, err := s.ValidateSession(ctx, &ValidateSessionRequest{SessionToken: token})
	if err != nil {
		return nil, err
	}
	if !resp.Valid {
		return nil, NewDomainError(ErrorUnauthenticated, "invalid session token", nil)
	}
	return resp, nil
}

// HasScope checks if a validated session has a specific scope.
func HasScope(session *ValidateSessionResponse, scope string) bool {
	for _, s := range session.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}
