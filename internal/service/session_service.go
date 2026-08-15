package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/auth"
	"github.com/envsync-cloud/minikms/internal/pki"
	"github.com/envsync-cloud/minikms/internal/pkistore"
	"github.com/envsync-cloud/minikms/internal/store"
)

// SessionPolicyStore defines the policy/token methods SessionService needs from the store.
type SessionPolicyStore interface {
	GetOrgSecurityPolicy(ctx context.Context, orgID string) (*store.OrgSecurityPolicy, error)
	GetTokensBySubject(ctx context.Context, subjectHash string) ([]*auth.TokenEntry, error)
	RevokeTokensBySubject(ctx context.Context, subjectHash string) (int, error)
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
}

// NewSessionService creates a new SessionService.
func NewSessionService(
	signingKey *ecdsa.PrivateKey,
	issuer string,
	defaultTTL time.Duration,
	registry auth.TokenRegistry,
	certStore pkistore.Store,
	policyStore SessionPolicyStore,
	auditLogger *audit.AuditLogger,
) *SessionService {
	return &SessionService{
		signingKey:  signingKey,
		issuer:      issuer,
		defaultTTL:  defaultTTL,
		registry:    registry,
		certStore:   certStore,
		policyStore: policyStore,
		auditLogger: auditLogger,
	}
}

// SessionClaims extends JWT claims with session-specific fields.
type SessionClaims struct {
	jwt.RegisteredClaims
	OrgID      string   `json:"org"`
	Role       string   `json:"role"`
	CertSerial string   `json:"cert_serial"`
	Scopes     []string `json:"scopes"`
}

// CreateSessionByCertRequest represents a BYOK/CLI certificate-based auth request.
type CreateSessionByCertRequest struct {
	CertPEM     string
	SignedNonce []byte
	Nonce       []byte
	Scopes      []string
}

// CreateSessionManagedRequest represents a web/managed auth request.
type CreateSessionManagedRequest struct {
	MemberID   string
	OrgID      string
	CertSerial string
	Scopes     []string
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

	// Parse the member certificate
	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil {
		return nil, NewDomainError(ErrorUnauthenticated, "certificate authentication failed", fmt.Errorf("invalid PEM certificate"))
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, NewDomainError(ErrorUnauthenticated, "certificate authentication failed", err)
	}

	// Extract ECDSA public key
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, NewDomainError(ErrorUnauthenticated, "certificate authentication failed",
			fmt.Errorf("certificate does not contain an ECDSA public key"))
	}

	// Verify the signed nonce
	hash := sha256.Sum256(req.Nonce)
	if !ecdsa.VerifyASN1(pubKey, hash[:], req.SignedNonce) {
		return nil, NewDomainError(ErrorUnauthenticated, "certificate authentication failed",
			fmt.Errorf("nonce signature verification failed"))
	}

	// Extract custom OIDs from cert
	memberID := pki.ExtractOIDValue(cert, pki.OIDMemberID)
	orgID := pki.ExtractOIDValue(cert, pki.OIDOrgID)
	role := pki.ExtractOIDValue(cert, pki.OIDRole)
	serialHex := cert.SerialNumber.Text(16)

	if memberID == "" || orgID == "" {
		return nil, NewDomainError(ErrorUnauthenticated, "certificate authentication failed",
			fmt.Errorf("certificate missing required OIDs"))
	}

	// Verify cert is not revoked
	certRecord, err := s.certStore.GetCertificateBySerial(ctx, serialHex)
	if err != nil {
		return nil, internalError("failed to check certificate status", err)
	}
	if certRecord == nil {
		return nil, NewDomainError(ErrorUnauthenticated, "certificate authentication failed",
			fmt.Errorf("certificate not found in registry"))
	}
	if certRecord.Status == "revoked" {
		return nil, NewDomainError(ErrorUnauthenticated, "certificate authentication failed",
			fmt.Errorf("certificate has been revoked"))
	}
	if certRecord.Status == "expired" || cert.NotAfter.Before(time.Now()) {
		return nil, NewDomainError(ErrorUnauthenticated, "certificate authentication failed",
			fmt.Errorf("certificate has expired"))
	}

	// Determine scopes
	scopes := s.resolveScopes(req.Scopes, role)

	// Issue session token
	return s.issueSessionToken(ctx, memberID, orgID, role, serialHex, scopes)
}

// CreateSessionManaged creates a session for a managed/web member (pre-authenticated via OIDC).
func (s *SessionService) CreateSessionManaged(ctx context.Context, req *CreateSessionManagedRequest) (*CreateSessionResponse, error) {
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := requireFields(
		requiredField("member_id", req.MemberID),
		requiredField("org_id", req.OrgID),
		requiredField("cert_serial", req.CertSerial),
	); err != nil {
		return nil, err
	}

	// Verify the cert exists and is active
	certRecord, err := s.certStore.GetCertificateBySerial(ctx, req.CertSerial)
	if err != nil {
		return nil, internalError("failed to check certificate status", err)
	}
	if certRecord == nil {
		return nil, NewDomainError(ErrorUnauthenticated, "managed authentication failed",
			fmt.Errorf("certificate not found"))
	}
	if certRecord.Status != "active" {
		return nil, NewDomainError(ErrorUnauthenticated, "managed authentication failed",
			fmt.Errorf("certificate is not active"))
	}
	if certRecord.OrgID != req.OrgID {
		return nil, NewDomainError(ErrorUnauthenticated, "managed authentication failed",
			fmt.Errorf("certificate organization mismatch"))
	}

	// Parse cert to extract role
	block, _ := pem.Decode([]byte(certRecord.CertPEM))
	if block == nil {
		return nil, internalError("invalid stored certificate PEM", nil)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, internalError("failed to parse stored certificate", err)
	}
	role := pki.ExtractOIDValue(cert, pki.OIDRole)

	// Determine scopes
	scopes := s.resolveScopes(req.Scopes, role)

	return s.issueSessionToken(ctx, req.MemberID, req.OrgID, role, req.CertSerial, scopes)
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

	// Verify cert serial is still valid
	if claims.CertSerial != "" {
		certRecord, err := s.certStore.GetCertificateBySerial(ctx, claims.CertSerial)
		if err != nil {
			return nil, internalError("failed to check session certificate", err)
		}
		if certRecord == nil || certRecord.Status != "active" {
			return &ValidateSessionResponse{Valid: false}, nil
		}
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

// RevokeMemberSessions invalidates all sessions for a member.
func (s *SessionService) RevokeMemberSessions(ctx context.Context, memberID, orgID string) (int, error) {
	if err := requireFields(
		requiredField("member_id", memberID),
		requiredField("org_id", orgID),
	); err != nil {
		return 0, err
	}

	subjectHash := auth.HashSubject(memberID)
	count, err := s.policyStore.RevokeTokensBySubject(ctx, subjectHash)
	if err != nil {
		return 0, internalError("failed to revoke member sessions", err)
	}

	_ = s.auditLogger.Log(ctx, orgID, "member_sessions_revoked", memberID,
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

// ListSessions returns active sessions for a member.
func (s *SessionService) ListSessions(ctx context.Context, memberID, orgID string) (*ListSessionsResponse, error) {
	if err := requireFields(
		requiredField("member_id", memberID),
		requiredField("org_id", orgID),
	); err != nil {
		return nil, err
	}

	subjectHash := auth.HashSubject(memberID)
	entries, err := s.policyStore.GetTokensBySubject(ctx, subjectHash)
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

// issueSessionToken creates and stores a JWT session token.
func (s *SessionService) issueSessionToken(ctx context.Context, memberID, orgID, role, certSerial string, scopes []string) (*CreateSessionResponse, error) {
	// Check session count limit
	policy, err := s.policyStore.GetOrgSecurityPolicy(ctx, orgID)
	if err != nil {
		return nil, internalError("failed to get org security policy", err)
	}

	subjectHash := auth.HashSubject(memberID)
	existingTokens, err := s.policyStore.GetTokensBySubject(ctx, subjectHash)
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
