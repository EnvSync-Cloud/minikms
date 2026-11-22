// Command minikms-rewrap re-seals organization master-key ciphertext under a new root key.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/rewrap"
)

func main() {
	if err := execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "minikms-rewrap: %v\n", err)
		os.Exit(1)
	}
}

func execute(args []string, stdout, stderr io.Writer) error {
	dryRun, confirm, newKeyFile, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}

	oldKey, err := rewrap.LoadCurrentRootKey(os.Getenv("MINIKMS_ROOT_KEY"), os.Getenv("MINIKMS_ROOT_KEY_FILE"))
	if err != nil {
		return err
	}
	defer crypto.ZeroizeBytes(oldKey)

	newKey, err := rewrap.LoadNewRootKey(newKeyFile)
	if err != nil {
		return err
	}
	defer crypto.ZeroizeBytes(newKey)

	opts := rewrap.Options{
		OldKey:  oldKey,
		NewKey:  newKey,
		DryRun:  dryRun,
		Confirm: confirm,
	}
	if err := rewrap.Validate(opts); err != nil {
		return err
	}

	dbURL := os.Getenv("MINIKMS_DB_URL")
	if dbURL == "" {
		return fmt.Errorf("MINIKMS_DB_URL is required")
	}
	ctx := context.Background()
	store, err := rewrap.NewPostgresStore(ctx, dbURL)
	if err != nil {
		return err
	}
	defer store.Close()
	return rewrap.Run(ctx, store, opts, stdout)
}

func parseFlags(args []string, stderr io.Writer) (dryRun bool, confirm bool, newKeyFile string, err error) {
	fs := flag.NewFlagSet("minikms-rewrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dry := fs.Bool("dry-run", true, "decrypt and trial-encrypt without writing (default true; set --dry-run=false with --confirm to commit)")
	ok := fs.Bool("confirm", false, "required with --dry-run=false to commit the rewrap")
	path := fs.String("new-key-file", "", "path to the new 32-byte hex root key file (required; not accepted via flags or environment)")
	fs.Usage = func() {
		out := fs.Output()
		_, _ = fmt.Fprintf(out, "usage: minikms-rewrap --new-key-file PATH [--dry-run=false --confirm]\n\n")
		_, _ = fmt.Fprintf(out, "Current root key: MINIKMS_ROOT_KEY_FILE or MINIKMS_ROOT_KEY\n")
		_, _ = fmt.Fprintf(out, "Database: MINIKMS_DB_URL\n")
		_, _ = fmt.Fprintf(out, "HKDF salt: MINIKMS_HKDF_SALT when the server sets it\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return false, false, "", err
	}
	if fs.NArg() != 0 {
		return false, false, "", fmt.Errorf("unexpected arguments")
	}
	return *dry, *ok, *path, nil
}
