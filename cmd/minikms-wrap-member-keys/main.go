// Command minikms-wrap-member-keys envelope-encrypts managed member key material at rest.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/envsync-cloud/minikms/internal/memberkey"
)

func main() {
	ignoreSIGPIPE()
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	mode, err := memberkey.ParseMode(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		writeErr(stderr, err)
		return 2
	}

	mgr, err := memberkey.LoadRootKey(os.Getenv("MINIKMS_ROOT_KEY"), os.Getenv("MINIKMS_ROOT_KEY_FILE"))
	if err != nil {
		writeErr(stderr, err)
		return 1
	}

	ctx := context.Background()
	store, err := memberkey.NewPostgresStore(ctx, os.Getenv("MINIKMS_DB_URL"))
	if err != nil {
		writeErr(stderr, err)
		return 1
	}
	defer store.Close()

	if err := memberkey.Run(ctx, store, mgr, mode, time.Time{}, stdout); err != nil {
		writeErr(stderr, err)
		return 1
	}
	return 0
}

func writeErr(stderr io.Writer, err error) {
	_, _ = fmt.Fprintf(stderr, "minikms-wrap-member-keys: %v\n", err)
}
