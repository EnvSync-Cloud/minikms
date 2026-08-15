// Command minikms-escrow provides the local, audited administrator workflow for
// exporting custodian shares and performing threshold recovery with re-sealing.
package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/escrow"
	"github.com/envsync-cloud/minikms/internal/store"
)

type repeatedFlag []string

func (f *repeatedFlag) String() string { return strings.Join(*f, ",") }
func (f *repeatedFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "export":
		err = runExport(ctx, os.Args[2:])
	case "recover":
		err = runRecover(ctx, os.Args[2:])
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "minikms-escrow: %v\n", err)
		os.Exit(1)
	}
}

func runExport(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	keyType := flags.String("key-type", "", "root or org_ca")
	orgID := flags.String("org-id", "", "organization ID for org_ca shares")
	custodianID := flags.String("custodian-id", "", "custodian that owns the share")
	actorID := flags.String("actor-id", "", "administrator performing the export")
	output := flags.String("out", "", "new 0600 share-package file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *custodianID == "" || *actorID == "" || *output == "" {
		return fmt.Errorf("--custodian-id, --actor-id, and --out are required")
	}
	scope, err := normalizeScope(*keyType, *orgID)
	if err != nil {
		return err
	}

	manager, pgStore, cleanup, err := openManager(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	_ = pgStore
	outputFile, discardOutput, err := createExclusive(*output)
	if err != nil {
		return fmt.Errorf("reserve share package output: %w", err)
	}
	defer func() { discardOutput() }()

	sharePackage, err := manager.ExportShare(ctx, scope, *keyType, *custodianID, *actorID)
	if err != nil {
		return err
	}
	defer crypto.ZeroizeBytes(sharePackage)
	if _, err := outputFile.Write(append(sharePackage, '\n')); err != nil {
		return fmt.Errorf("write share package: %w", err)
	}
	if err := outputFile.Close(); err != nil {
		return fmt.Errorf("close share package: %w", err)
	}
	discardOutput = func() {}
	fmt.Printf("exported share for custodian %s to %s\n", *custodianID, *output)
	return nil
}

func runRecover(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("recover", flag.ContinueOnError)
	keyType := flags.String("key-type", "", "root or org_ca")
	orgID := flags.String("org-id", "", "organization ID for org_ca shares")
	actorID := flags.String("actor-id", "", "administrator performing recovery")
	output := flags.String("out", "", "new 0600 recovered-key file")
	var sharePaths repeatedFlag
	flags.Var(&sharePaths, "share", "custodian share-package file; repeat at least K times")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *actorID == "" || *output == "" || len(sharePaths) == 0 {
		return fmt.Errorf("--actor-id, --out, and repeated --share flags are required")
	}
	scope, err := normalizeScope(*keyType, *orgID)
	if err != nil {
		return err
	}

	packages := make([][]byte, len(sharePaths))
	for i, path := range sharePaths {
		data, err := readProtectedFile(path)
		if err != nil {
			zeroizeAll(packages)
			return fmt.Errorf("read share package %q: %w", path, err)
		}
		packages[i] = data
	}
	defer zeroizeAll(packages)

	manager, pgStore, cleanup, err := openManager(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	_ = pgStore
	outputFile, discardOutput, err := createExclusive(*output)
	if err != nil {
		return fmt.Errorf("reserve recovered-key output: %w", err)
	}
	defer func() { discardOutput() }()

	recovered, newSet, err := manager.RecoverAndReseal(ctx, scope, *keyType, packages, *actorID)
	if err != nil {
		return err
	}
	defer crypto.ZeroizeBytes(recovered)

	outputData, err := formatRecoveredKey(*keyType, recovered)
	if err != nil {
		return err
	}
	defer crypto.ZeroizeBytes(outputData)
	if _, err := outputFile.Write(outputData); err != nil {
		return fmt.Errorf("write recovered key: %w", err)
	}
	if err := outputFile.Close(); err != nil {
		return fmt.Errorf("close recovered key: %w", err)
	}
	discardOutput = func() {}
	fmt.Printf("recovery succeeded and re-sealed as set %s; key written to %s\n", newSet.ID, *output)
	return nil
}

func openManager(ctx context.Context) (*escrow.Manager, *store.PostgresStore, func(), error) {
	dbURL := os.Getenv("MINIKMS_DB_URL")
	if dbURL == "" {
		return nil, nil, func() {}, fmt.Errorf("MINIKMS_DB_URL is required")
	}
	sealKey, err := escrow.LoadSealKey(os.Getenv("MINIKMS_ESCROW_SEAL_KEY"), os.Getenv("MINIKMS_ESCROW_SEAL_KEY_FILE"))
	if err != nil {
		return nil, nil, func() {}, err
	}
	defer crypto.ZeroizeBytes(sealKey)

	pgStore, err := store.NewPostgresStore(ctx, dbURL)
	if err != nil {
		return nil, nil, func() {}, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	manager, err := escrow.NewManager(pgStore, audit.NewAuditLogger(pgStore), sealKey)
	if err != nil {
		pgStore.Close()
		return nil, nil, func() {}, err
	}
	return manager, pgStore, pgStore.Close, nil
}

func normalizeScope(keyType, orgID string) (string, error) {
	switch keyType {
	case escrow.KeyTypeRoot:
		if orgID != "" && orgID != escrow.RootScope {
			return "", fmt.Errorf("--org-id is not used for root recovery")
		}
		return escrow.RootScope, nil
	case escrow.KeyTypeOrgCA:
		if orgID == "" {
			return "", fmt.Errorf("--org-id is required for org_ca recovery")
		}
		return orgID, nil
	default:
		return "", fmt.Errorf("--key-type must be root or org_ca")
	}
}

func formatRecoveredKey(keyType string, recovered []byte) ([]byte, error) {
	if keyType == escrow.KeyTypeRoot {
		encoded := make([]byte, hex.EncodedLen(len(recovered))+1)
		hex.Encode(encoded, recovered)
		encoded[len(encoded)-1] = '\n'
		return encoded, nil
	}
	key, err := crypto.UnmarshalECPrivateKey(recovered)
	if err != nil {
		return nil, fmt.Errorf("recovered org CA key is invalid: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal recovered org CA key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func createExclusive(path string) (*os.File, func(), error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, func() {}, err
	}
	discard := func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	return file, discard, nil
}

func readProtectedFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("permissions must be 0600 or stricter")
	}
	return os.ReadFile(path)
}

func zeroizeAll(values [][]byte) {
	for _, value := range values {
		crypto.ZeroizeBytes(value)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: minikms-escrow <export|recover> [flags]")
}
