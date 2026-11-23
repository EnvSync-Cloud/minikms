// Command minikms-rewrap re-seals organization master-key ciphertext under a new root key.
//
// Exit status 0 is success, including -h. Exit status 1 means the rewrap was
// not committed. Exit status 3 means the rewrap committed and the count report
// could not be written; miniKMS must now be started with the new root key.
// Exit status 4 means the commit outcome is unknown.
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

// exitCommittedReportFailed means the rewrap transaction committed and the
// count report could not be written. miniKMS must now be started with the
// new root key.
const exitCommittedReportFailed = 3

// exitCommitOutcomeUnknown means Commit returned an error, so it is unknown
// whether the rewrap was committed.
const exitCommitOutcomeUnknown = 4

func main() {
	ignoreSIGPIPE()
	os.Exit(handle(execute(os.Args[1:], os.Stdout, os.Stderr), os.Stderr))
}

// exitCode maps a rewrap result to a process status. Status 1 means the
// rewrap was not committed. Status 3 means it committed and the report
// failed. Status 4 means the commit outcome is unknown.
func exitCode(err error) int {
	switch {
	case err == nil || errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, rewrap.ErrCommittedReportFailed):
		return exitCommittedReportFailed
	case errors.Is(err, rewrap.ErrCommitOutcomeUnknown):
		return exitCommitOutcomeUnknown
	default:
		return 1
	}
}

func handle(err error, stderr io.Writer) int {
	code := exitCode(err)
	if code == 0 {
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "minikms-rewrap: %v\n", err)
	return code
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
		_, _ = fmt.Fprintf(out, "HKDF salt: MINIKMS_HKDF_SALT when the server sets it\n")
		_, _ = fmt.Fprintf(out, "Member-key envelopes are re-sealed with the same associated data.\n")
		_, _ = fmt.Fprintf(out, "Empty member rows and member rows in the previous encoding are left unchanged.\n")
		_, _ = fmt.Fprintf(out, "Exit status 1: the rewrap was not committed.\n")
		_, _ = fmt.Fprintf(out, "Exit status 3: the rewrap committed and the report could not be written. miniKMS must now be started with the new root key.\n")
		_, _ = fmt.Fprintf(out, "Exit status 4: the commit outcome is unknown. Keep miniKMS stopped. "+
			"Check A: dry-run with the old key as MINIKMS_ROOT_KEY_FILE and a valid, distinct trial key "+
			"(a freshly generated 32-byte hex key in a mode-0600 file, different from both the old and new keys) as --new-key-file. "+
			"Check B: dry-run with the new key as MINIKMS_ROOT_KEY_FILE and the same valid, distinct trial key as --new-key-file. "+
			"A check is conclusive only if it exits 0, reports zero failures, and scanned at least one in-scope row (key_versions + certificates scanned + opened member-key envelopes > 0, printed as total scanned). "+
			"Only if Check A is conclusive: the commit did not land; keep the old key. "+
			"Only if Check B is conclusive: the commit landed; start miniKMS with the new key. "+
			"If both checks scan zero rows, or neither is conclusive, the outcome stays unknown: "+
			"keep miniKMS stopped and restore from the pre-rotation DB dump with the old key (or investigate). "+
			"Delete the trial key file afterwards.\n\n")
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
