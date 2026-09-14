package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadRootCAFromSources reads a root CA from exactly one certificate source
// and exactly one private-key source. File sources are intended for mounted
// Kubernetes or external-secret volumes.
func LoadRootCAFromSources(certValue, certFile, keyValue, keyFile string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := loadInjectedPEM("root CA certificate", certValue, certFile, false)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := loadInjectedPEM("root CA private key", keyValue, keyFile, true)
	if err != nil {
		return nil, nil, err
	}
	return LoadRootCA(certPEM, keyPEM)
}

func loadInjectedPEM(name, value, path string, private bool) ([]byte, error) {
	if value == "" && path == "" {
		return nil, fmt.Errorf("%s is not configured", name)
	}
	if value != "" && path != "" {
		return nil, fmt.Errorf("configure only one %s source", name)
	}
	if value != "" {
		return []byte(value), nil
	}

	if private {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat %s file: %w", name, err)
		}
		if info.Mode().Perm()&0o027 != 0 {
			return nil, fmt.Errorf("%s file must not be group-writable or accessible by other users", name)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", name, err)
	}
	return data, nil
}
