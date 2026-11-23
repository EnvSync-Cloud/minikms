package testutil

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/envsync-cloud/minikms/internal/auth"
	"github.com/envsync-cloud/minikms/internal/pkistore"
)

func TestMockTokenRegistry_GetTokenReadsCertificateStatus(t *testing.T) {
	ctx := context.Background()
	reg := NewMockTokenRegistry()
	certs := map[string]string{
		"live": "active",
		"dead": "revoked",
	}
	reg.BindCertificateStatus(func(_ context.Context, serial string) (string, bool, error) {
		status, ok := certs[serial]
		return status, ok, nil
	})

	store := func(jti, serial string) {
		t.Helper()
		if err := reg.StoreToken(ctx, &auth.TokenEntry{
			JTI:         jti,
			SubjectHash: "subject",
			JWTHash:     "hash",
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(time.Hour),
			CertSerial:  serial,
		}); err != nil {
			t.Fatalf("StoreToken: %v", err)
		}
	}
	store("live-session", "live")
	store("dead-session", "dead")
	store("missing-session", "missing")
	store("non-cert", "")

	live, err := reg.GetToken(ctx, "live-session")
	if err != nil || live == nil || live.CertStatus != "active" || live.Revoked {
		t.Fatalf("live lookup = %+v err=%v", live, err)
	}
	dead, err := reg.GetToken(ctx, "dead-session")
	if err != nil || dead == nil || dead.CertStatus != "revoked" || dead.Revoked {
		t.Fatalf("revoked cert lookup = %+v err=%v", dead, err)
	}
	missing, err := reg.GetToken(ctx, "missing-session")
	if err != nil || missing == nil || missing.CertStatus != "" || missing.CertSerial != "missing" {
		t.Fatalf("missing cert lookup = %+v err=%v", missing, err)
	}
	nonCert, err := reg.GetToken(ctx, "non-cert")
	if err != nil || nonCert == nil || nonCert.CertSerial != "" || nonCert.CertStatus != "" {
		t.Fatalf("non-cert lookup = %+v err=%v", nonCert, err)
	}

	reg.BindCertificateStatus(func(context.Context, string) (string, bool, error) {
		return "", false, errors.New("lookup failed")
	})
	if _, err := reg.GetToken(ctx, "live-session"); err == nil {
		t.Fatal("certificate lookup error was ignored")
	}
}

func TestMockPKICertStore_RevokeCertificateEndsSessions(t *testing.T) {
	ctx := context.Background()
	certs := NewMockPKICertStore()
	reg := NewMockTokenRegistry()
	certs.BindTokenRevoker(reg)
	reg.BindCertificateStatus(func(ctx context.Context, serial string) (string, bool, error) {
		rec, err := certs.GetCertificateBySerial(ctx, serial)
		if err != nil || rec == nil {
			return "", false, err
		}
		return rec.Status, true, nil
	})

	for _, serial := range []string{"revoked-serial", "live-serial"} {
		if err := certs.StoreCertificate(ctx, &pkistore.CertRecord{
			SerialNumber: serial,
			CertType:     "member",
			OrgID:        "org-1",
			SubjectCN:    serial,
			CertPEM:      "cert",
			Status:       "active",
			IssuedAt:     time.Now().Add(-time.Hour),
			ExpiresAt:    time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("StoreCertificate: %v", err)
		}
	}
	store := func(jti, serial string) {
		t.Helper()
		if err := reg.StoreToken(ctx, &auth.TokenEntry{
			JTI: jti, SubjectHash: "s", JWTHash: "h",
			IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), CertSerial: serial,
		}); err != nil {
			t.Fatalf("StoreToken: %v", err)
		}
	}
	store("gone-1", "revoked-serial")
	store("gone-2", "revoked-serial")
	store("stay", "live-serial")
	store("plain", "")

	if err := certs.RevokeCertificate(ctx, "revoked-serial", &pkistore.CRLEntryRecord{
		CertSerial: "revoked-serial", IssuerSerial: "issuer", RevokedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	for _, jti := range []string{"gone-1", "gone-2"} {
		got, err := reg.GetToken(ctx, jti)
		if err != nil || got == nil || !got.Revoked || got.CertStatus != "revoked" {
			t.Fatalf("%s = %+v err=%v", jti, got, err)
		}
	}
	stay, err := reg.GetToken(ctx, "stay")
	if err != nil || stay == nil || stay.Revoked || stay.CertStatus != "active" {
		t.Fatalf("control = %+v err=%v", stay, err)
	}
	plain, err := reg.GetToken(ctx, "plain")
	if err != nil || plain == nil || plain.Revoked {
		t.Fatalf("non-cert = %+v err=%v", plain, err)
	}
	crl, err := certs.GetCertRevocationEntry(ctx, "revoked-serial")
	if err != nil || crl == nil {
		t.Fatalf("crl = %+v err=%v", crl, err)
	}

	if err := certs.RevokeCertificate(ctx, "missing", &pkistore.CRLEntryRecord{CertSerial: "missing"}); err == nil {
		t.Fatal("expected error for an unknown certificate")
	}
	if plain, err = reg.GetToken(ctx, "plain"); err != nil || plain.Revoked {
		t.Fatalf("unknown revoke changed non-cert token: %+v err=%v", plain, err)
	}
}

func TestMockPKICertStore_RevokeCertificateRollsBack(t *testing.T) {
	ctx := context.Background()
	certs := NewMockPKICertStore()
	if err := certs.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: "serial-1",
		CertType:     "member",
		OrgID:        "org-1",
		SubjectCN:    "member",
		CertPEM:      "cert",
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("StoreCertificate: %v", err)
	}
	certs.BindTokenRevoker(errTokenRevoker{})

	err := certs.RevokeCertificate(ctx, "serial-1", &pkistore.CRLEntryRecord{
		CertSerial: "serial-1", IssuerSerial: "issuer", RevokedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected token revoke error")
	}
	rec, getErr := certs.GetCertificateBySerial(ctx, "serial-1")
	if getErr != nil || rec == nil || rec.Status != "active" {
		t.Fatalf("status after failed revoke = %+v err=%v", rec, getErr)
	}
	crl, getErr := certs.GetCertRevocationEntry(ctx, "serial-1")
	if getErr != nil || crl != nil {
		t.Fatalf("crl after failed revoke = %+v err=%v", crl, getErr)
	}
}

func TestMockPKICertStore_RevokeCertificateRollbackKeepsOtherCRL(t *testing.T) {
	ctx := context.Background()
	certs := NewMockPKICertStore()
	if err := certs.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: "serial-1",
		CertType:     "member",
		OrgID:        "org-1",
		SubjectCN:    "member",
		CertPEM:      "cert",
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("StoreCertificate: %v", err)
	}
	otherAt := time.Now().UTC().Add(time.Second)
	certs.BindTokenRevoker(crlThenFailRevoker{certs: certs, at: otherAt})

	err := certs.RevokeCertificate(ctx, "serial-1", &pkistore.CRLEntryRecord{
		CertSerial: "serial-1", IssuerSerial: "issuer", RevokedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected token revoke error")
	}
	revoked, getErr := certs.GetCertRevocationEntry(ctx, "serial-1")
	if getErr != nil || revoked != nil {
		t.Fatalf("failed revoke CRL = %+v err=%v", revoked, getErr)
	}
	other, getErr := certs.GetCertRevocationEntry(ctx, "other-serial")
	if getErr != nil || other == nil || !other.RevokedAt.Equal(otherAt) {
		t.Fatalf("other CRL = %+v err=%v", other, getErr)
	}
}

type crlThenFailRevoker struct {
	certs *MockPKICertStore
	at    time.Time
}

func (r crlThenFailRevoker) RevokeTokensByCertSerial(ctx context.Context, _ string) error {
	if err := r.certs.InsertCRLEntry(ctx, &pkistore.CRLEntryRecord{
		CertSerial: "other-serial", IssuerSerial: "issuer", RevokedAt: r.at,
	}); err != nil {
		return err
	}
	return errors.New("token revoke failed")
}

type errTokenRevoker struct{}

func (errTokenRevoker) RevokeTokensByCertSerial(context.Context, string) error {
	return errors.New("token revoke failed")
}
