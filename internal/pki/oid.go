package pki

import (
	"crypto/x509"
	"encoding/asn1"
)

// PEN arc OIDs for EnvSync miniKMS.
// Uses 1.3.6.1.4.1.XXXXX (Private Enterprise Number arc).
// XXXXX is a placeholder until IANA PEN registration is complete.
var (
	// OIDEnvSyncArc is the base OID for EnvSync extensions.
	OIDEnvSyncArc = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999}

	// OIDOrgID identifies the organization ID in certificate extensions.
	OIDOrgID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

	// OIDRole identifies the role/permission level in certificate extensions.
	OIDRole = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}

	// OIDMemberID identifies the member/user ID in certificate extensions.
	OIDMemberID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 3}
)

// ExtractOIDValue extracts a string value from a certificate extension by OID.
// Returns empty string if the OID is not found.
func ExtractOIDValue(cert *x509.Certificate, oid asn1.ObjectIdentifier) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			var value string
			if _, err := asn1.Unmarshal(ext.Value, &value); err == nil {
				return value
			}
			// Try raw bytes as UTF-8
			return string(ext.Value)
		}
	}
	return ""
}
