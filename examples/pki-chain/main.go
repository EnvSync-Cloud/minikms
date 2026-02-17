// Package main demonstrates the miniKMS PKI certificate chain:
// Root CA → Org Intermediate CA → Member Certificate, plus CRL generation.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/envsync/minikms/internal/pki"
)

func main() {
	fmt.Println("=== miniKMS PKI Chain Demo ===")
	fmt.Println()

	// 1. Create Root CA
	fmt.Println("1. Creating Root CA (P-384, self-signed, MaxPathLen:1)")
	rootCert, rootKey, _, err := pki.CreateRootCA("EnvSync Root CA", 10*365*24*time.Hour)
	if err != nil {
		log.Fatalf("CreateRootCA: %v", err)
	}
	fmt.Printf("   CN: %s\n", rootCert.Subject.CommonName)
	fmt.Printf("   Serial: %s\n", rootCert.SerialNumber.Text(16))
	fmt.Printf("   IsCA: %v, MaxPathLen: %d\n", rootCert.IsCA, rootCert.MaxPathLen)
	fmt.Printf("   Valid: %s to %s\n", rootCert.NotBefore.Format("2006-01-02"), rootCert.NotAfter.Format("2006-01-02"))

	// Verify self-signed
	err = rootCert.CheckSignatureFrom(rootCert)
	fmt.Printf("   Self-signed: %v\n", err == nil)

	// 2. Create Org Intermediate CA
	fmt.Println()
	fmt.Println("2. Creating Org Intermediate CA (P-384, MaxPathLen:0)")
	orgCert, orgKey, _, err := pki.CreateOrgIntermediateCA(
		"org-acme-corp", "Acme Corp", rootCert, rootKey, 5*365*24*time.Hour,
	)
	if err != nil {
		log.Fatalf("CreateOrgIntermediateCA: %v", err)
	}
	fmt.Printf("   CN: %s\n", orgCert.Subject.CommonName)
	fmt.Printf("   OU: %v\n", orgCert.Subject.OrganizationalUnit)
	fmt.Printf("   Serial: %s\n", orgCert.SerialNumber.Text(16))
	fmt.Printf("   IsCA: %v, MaxPathLen: %d\n", orgCert.IsCA, orgCert.MaxPathLen)

	// Verify signed by root
	err = orgCert.CheckSignatureFrom(rootCert)
	fmt.Printf("   Signed by Root CA: %v\n", err == nil)

	// 3. Issue Member Certificate
	fmt.Println()
	fmt.Println("3. Issuing Member Certificate (P-256, IsCA:false, ClientAuth)")
	memberCert, _, _, err := pki.CreateMemberCertificate(
		"member-alice-001", "alice@acme.com", "org-acme-corp", "admin",
		orgCert, orgKey, 365*24*time.Hour,
		[]string{"http://crl.envsync.dev/acme.crl"},
	)
	if err != nil {
		log.Fatalf("CreateMemberCertificate: %v", err)
	}
	fmt.Printf("   CN: %s\n", memberCert.Subject.CommonName)
	fmt.Printf("   Serial: %s\n", memberCert.SerialNumber.Text(16))
	fmt.Printf("   IsCA: %v\n", memberCert.IsCA)
	fmt.Printf("   ExtKeyUsage: ClientAuth=%v\n", hasClientAuth(memberCert))
	fmt.Printf("   CRL Dist Points: %v\n", memberCert.CRLDistributionPoints)

	// Verify chain of trust
	err = memberCert.CheckSignatureFrom(orgCert)
	fmt.Printf("   Signed by Org CA: %v\n", err == nil)

	// 4. Full chain verification using x509.CertPool
	fmt.Println()
	fmt.Println("4. Full Chain Verification")
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(orgCert)

	chains, err := memberCert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		fmt.Printf("   Chain verification FAILED: %v\n", err)
	} else {
		fmt.Printf("   Chain verified! Length: %d\n", len(chains[0]))
		for i, cert := range chains[0] {
			fmt.Printf("   [%d] %s (serial: %s)\n", i, cert.Subject.CommonName, cert.SerialNumber.Text(16))
		}
	}

	// 5. Generate CRL and check revocation
	fmt.Println()
	fmt.Println("5. CRL Generation & Revocation Check")
	now := time.Now()

	// Generate CRL with the member cert revoked
	revokedCerts := []pki.RevokedCert{
		{
			SerialNumber: memberCert.SerialNumber,
			RevokedAt:    now,
			ReasonCode:   1, // keyCompromise
		},
	}
	crlDER, err := pki.GenerateCRL(orgCert, orgKey, revokedCerts, pki.CRLConfig{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	})
	if err != nil {
		log.Fatalf("GenerateCRL: %v", err)
	}
	fmt.Printf("   CRL generated: %d bytes\n", len(crlDER))

	// Parse and verify CRL
	rl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		log.Fatalf("ParseRevocationList: %v", err)
	}
	err = rl.CheckSignatureFrom(orgCert)
	fmt.Printf("   CRL signed by Org CA: %v\n", err == nil)
	fmt.Printf("   Revoked entries: %d\n", len(rl.RevokedCertificateEntries))

	// Check revocation status
	status := pki.CheckRevocationStatus(memberCert.SerialNumber, revokedCerts)
	fmt.Printf("   Member cert status: %s\n", statusString(status.Status))

	// Check a non-revoked serial
	status2 := pki.CheckRevocationStatus(big.NewInt(999999), revokedCerts)
	fmt.Printf("   Unknown cert status: %s\n", statusString(status2.Status))

	// Print PEM for visual inspection
	fmt.Println()
	fmt.Println("6. Root CA Certificate (PEM)")
	rootPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCert.Raw,
	})
	fmt.Println(string(rootPEM))

	fmt.Println("=== Demo Complete ===")
}

func hasClientAuth(cert *x509.Certificate) bool {
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func statusString(s pki.OCSPStatus) string {
	switch s {
	case pki.OCSPStatusGood:
		return "Good"
	case pki.OCSPStatusRevoked:
		return "Revoked"
	default:
		return "Unknown"
	}
}
