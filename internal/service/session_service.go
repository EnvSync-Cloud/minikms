package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/envsync/minikms/internal/audit"
	"github.com/envsync/minikms/internal/auth"
	"github.com/envsync/minikms/internal/pki"
	"github.com/envsync/minikms/internal/pkistore"
	"github.com/envsync/minikms/internal/store"
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
	// Parse the member certificate
	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Extract ECDSA public key
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain an ECDSA public key")
	}

	// Verify the signed nonce
	hash := sha256.Sum256(req.Nonce)
	if !ecdsa.VerifyASN1(pubKey, hash[:], req.SignedNonce) {
		return nil, fmt.Errorf("nonce signature verification failed")
	}

	// Extract custom OIDs from cert
	memberID := pki.ExtractOIDValue(cert, pki.OIDMemberID)
	orgID := pki.ExtractOIDValue(cert, pki.OIDOrgID)
	role := pki.ExtractOIDValue(cert, pki.OIDRole)
	serialHex := cert.SerialNumber.Text(16)

	if memberID == "" || orgID == "" {
		return nil, fmt.Errorf("certificate missing required OIDs (member_id, org_id)")
	}

	// Verify cert is not revoked
	certRecord, err := s.certStore.GetCertificateBySerial(ctx, serialHex)
	if err != nil {
		return nil, fmt.Errorf("failed to check certificate status: %w", err)
	}
	if certRecord == nil {
		return nil, fmt.Errorf("certificate not found in registry")
	}
	if certRecord.Status == "revoked" {
		return nil, fmt.Errorf("certificate has been revoked")
	}
	if certRecord.Status == "expired" || cert.NotAfter.Before(time.Now()) {
		return nil, fmt.Errorf("certificate has expired")
	}

	// Determine scopes
	scopes := s.resolveScopes(req.Scopes, role)

	// Issue session token
	return s.issueSessionToken(ctx, memberID, orgID, role, serialHex, scopes)
}

// CreateSessionManaged creates a session for a managed/web member (pre-authenticated via OIDC).
func (s *SessionService) CreateSessionManaged(ctx context.Context, req *CreateSessionManagedRequest) (*CreateSessionResponse, error) {
	// Verify the cert exists and is active
	certRecord, err := s.certStore.GetCertificateBySerial(ctx, req.CertSerial)
	if err != nil {
		return nil, fmt.Errorf("failed to check certificate status: %w", err)
	}
	if certRecord == nil {
		return nil, fmt.Errorf("certificate not found")
	}
	if certRecord.Status != "active" {
		return nil, fmt.Errorf("certificate is not active (status: %s)", certRecord.Status)
	}
	if certRecord.OrgID != req.OrgID {
		return nil, fmt.Errorf("certificate does not belong to org %s", req.OrgID)
	}

	// Parse cert to extract role
	block, _ := pem.Decode([]byte(certRecord.CertPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid stored certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stored certificate: %w", err)
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
	if err != nil || entry == nil {
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
		if err != nil || certRecord == nil || certRecord.Status != "active" {
			return &ValidateSessionResponse{Valid: false}, nil
		}
	}

	return &ValidateSessionResponse{
		Valid:      true,
		MemberID:  claims.Subject,
		OrgID:     claims.OrgID,
		Role:      claims.Role,
		CertSerial: claims.CertSerial,
		Scopes:    claims.Scopes,
		ExpiresAt: claims.ExpiresAt.Time,
	}, nil
}

// RevokeSession invalidates a session token.
func (s *SessionService) RevokeSession(ctx context.Context, sessionToken string) error {
	// Parse to get JTI
	claims := &SessionClaims{}
	_, err := jwt.ParseWithClaims(sessionToken, claims, func(token *jwt.Token) (interface{}, error) {
		return &s.signingKey.PublicKey, nil
	})
	if err != nil {
		return fmt.Errorf("invalid session token: %w", err)
	}

	if err := s.registry.RevokeToken(ctx, claims.ID); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	_ = s.auditLogger.Log(ctx, claims.OrgID, "session_revoked", claims.Subject,
		fmt.Sprintf("Session %s revoked", claims.ID), "")

	return nil
}

// RevokeMemberSessions invalidates all sessions for a member.
func (s *SessionService) RevokeMemberSessions(ctx context.Context, memberID, orgID string) (int, error) {
	subjectHash := auth.HashSubject(memberID)
	count, err := s.policyStore.RevokeTokensBySubject(ctx, subjectHash)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke member sessions: %w", err)
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
	subjectHash := auth.HashSubject(memberID)
	entries, err := s.policyStore.GetTokensBySubject(ctx, subjectHash)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
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
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// issueSessionToken creates and stores a JWT session token.
func (s *SessionService) issueSessionToken(ctx context.Context, memberID, orgID, role, certSerial string, scopes []string) (*CreateSessionResponse, error) {
	// Check session count limit
	policy, err := s.policyStore.GetOrgSecurityPolicy(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get org security policy: %w", err)
	}

	subjectHash := auth.HashSubject(memberID)
	existingTokens, err := s.policyStore.GetTokensBySubject(ctx, subjectHash)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing sessions: %w", err)
	}

	activeCount := 0
	for _, t := range existingTokens {
		if !t.Revoked && t.ExpiresAt.After(time.Now()) {
			activeCount++
		}
	}
	if activeCount >= policy.MaxSessionTokens {
		return nil, fmt.Errorf("maximum number of active sessions (%d) reached for member", policy.MaxSessionTokens)
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
		return nil, fmt.Errorf("failed to sign session token: %w", err)
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
		return nil, fmt.Errorf("failed to store session token: %w", err)
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
		"master":     {"vault:read", "vault:write", "vault:delete", "pki:issue"},
		"admin":      {"vault:read", "vault:write", "vault:delete", "pki:issue"},
		"member":     {"vault:read", "vault:write"},
		"developer":  {"vault:read", "vault:write"},
		"readonly":   {"vault:read"},
		"viewer":     {"vault:read"},
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
	resp, err := s.ValidateSession(ctx, &ValidateSessionRequest{SessionToken: token})
	if err != nil {
		return nil, err
	}
	if !resp.Valid {
		return nil, fmt.Errorf("invalid session token")
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

// GenerateSessionSigningKey generates an ECDSA P-256 key for JWT signing.
func GenerateSessionSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session signing key: %w", err)
	}
	return key, nil
}

