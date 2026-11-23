// Package memberkey envelope-encrypts managed member key material at rest.
// Organization CA rows, leaf rows, and member rows without key material are left unchanged.
package memberkey

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/keys"
)

const certTypeMember = "member"

// Mode selects a wrap-member-keys run.
type Mode int

const (
	// ModeDryRun counts rows and writes nothing.
	ModeDryRun Mode = iota
	// ModeCheck prints a read-only leftover report.
	ModeCheck
	// ModeConfirm wraps member rows in one transaction.
	ModeConfirm
)

var (
	// ErrClassificationFailed means at least one member row was neither an
	// envelope nor the previous encoding. No rows are updated.
	ErrClassificationFailed = errors.New("member key wrap aborted because one or more member rows could not be classified; no rows were updated")

	// ErrVerifyFailed means a wrapped row did not open to the same key material.
	// No rows are updated.
	ErrVerifyFailed = errors.New("member key wrap aborted because a wrapped row did not open to the same key material; no rows were updated")

	// ErrNoWrappedAnchor means --confirm would rewrite legacy rows without an
	// existing envelope that opens under this root key.
	ErrNoWrappedAnchor = errors.New("member key wrap refused: no existing wrapped member key opened with this root key, so the configuration was not checked; no rows were updated")
)

// Row is one certificate record needed to classify member key material.
type Row struct {
	ID                  string
	SerialNumber        string
	CertType            string
	OrgID               string
	Status              string
	ExpiresAt           time.Time
	EncryptedPrivateKey []byte
}

// Store opens a wrap transaction.
type Store interface {
	Begin(ctx context.Context, readOnly bool) (Tx, error)
}

// Tx is one wrap transaction. Updates stay uncommitted until Commit.
type Tx interface {
	ListCertificates(ctx context.Context) ([]Row, error)
	// UpdateMemberKey replaces member key material when id is a member row and
	// the stored bytes still equal previous. It must not update other cert types.
	UpdateMemberKey(ctx context.Context, id string, previous, wrapped []byte) error
	ReadMemberKey(ctx context.Context, id string) ([]byte, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// DryRunReport is the counts object printed by a dry run and by --confirm.
// A member row is active when its status is "active" and its expires_at is
// strictly after the run time. Revoked, expired, pending, and any other status
// are non-active, as is an active row whose expires_at is at or before the run time.
type DryRunReport struct {
	ToWrap                  int `json:"to_wrap"`
	ToWrapActive            int `json:"to_wrap_active"`
	ToWrapNonActive         int `json:"to_wrap_non_active"`
	AlreadyWrapped          int `json:"already_wrapped"`
	AlreadyWrappedActive    int `json:"already_wrapped_active"`
	AlreadyWrappedNonActive int `json:"already_wrapped_non_active"`
	Empty                   int `json:"empty"`
	SkippedNonMember        int `json:"skipped_non_member"`
	Failed                  int `json:"failed"`
}

// CheckReport is the counts object printed by --check.
type CheckReport struct {
	RawMember        int `json:"raw_member"`
	WrappedMember    int `json:"wrapped_member"`
	EmptyMember      int `json:"empty_member"`
	SkippedNonMember int `json:"skipped_non_member"`
	Failed           int `json:"failed"`
}

type tally struct {
	raw              int
	rawActive        int
	rawNonActive     int
	wrapped          int
	wrappedActive    int
	wrappedNonActive int
	empty            int
	skipped          int
	failed           int
}

func (t *tally) addRaw(active bool) {
	t.raw++
	if active {
		t.rawActive++
		return
	}
	t.rawNonActive++
}

func (t *tally) addWrapped(active bool) {
	t.wrapped++
	if active {
		t.wrappedActive++
		return
	}
	t.wrappedNonActive++
}

func (t tally) dryRunReport() DryRunReport {
	return DryRunReport{
		ToWrap:                  t.raw,
		ToWrapActive:            t.rawActive,
		ToWrapNonActive:         t.rawNonActive,
		AlreadyWrapped:          t.wrapped,
		AlreadyWrappedActive:    t.wrappedActive,
		AlreadyWrappedNonActive: t.wrappedNonActive,
		Empty:                   t.empty,
		SkippedNonMember:        t.skipped,
		Failed:                  t.failed,
	}
}

func (t tally) checkReport() CheckReport {
	return CheckReport{
		RawMember:        t.raw,
		WrappedMember:    t.wrapped,
		EmptyMember:      t.empty,
		SkippedNonMember: t.skipped,
		Failed:           t.failed,
	}
}

// rowActive reports whether a certificate row counts as active.
// Active means status is "active" and expiresAt is strictly after now.
// Revoked, expired, pending, and any other status are non-active. An active
// row whose expiresAt is at or before now is also non-active.
func rowActive(status string, expiresAt, now time.Time) bool {
	return status == "active" && expiresAt.After(now)
}

type wrapJob struct {
	id       string
	orgID    string
	serial   string
	previous []byte
	plain    []byte
}

type secretBufs struct {
	bufs [][]byte
}

func (s *secretBufs) track(b []byte) {
	if len(b) == 0 {
		return
	}
	s.bufs = append(s.bufs, b)
}

func (s *secretBufs) zeroize() {
	for _, b := range s.bufs {
		crypto.ZeroizeBytes(b)
	}
	s.bufs = nil
}

// ParseMode reads wrap-member-keys flags.
// No flags selects a dry run. --check selects the leftover report.
// --confirm selects the writing run.
func ParseMode(args []string, stderr io.Writer) (Mode, error) {
	if stderr == nil {
		stderr = io.Discard
	}
	fs := flag.NewFlagSet("minikms-wrap-member-keys", flag.ContinueOnError)
	var flagBuf bytes.Buffer
	fs.SetOutput(&flagBuf)
	check := fs.Bool("check", false, "read-only leftover report")
	confirm := fs.Bool("confirm", false, "wrap member key rows in one transaction")
	fs.Usage = func() {
		out := fs.Output()
		_, _ = fmt.Fprintf(out, "usage: minikms-wrap-member-keys [--check | --confirm]\n\n")
		_, _ = fmt.Fprintf(out, "Envelope-encrypt managed member key material at rest.\n")
		_, _ = fmt.Fprintf(out, "The default is a read-only dry run that prints counts only.\n")
		_, _ = fmt.Fprintf(out, "--confirm wraps member rows in one transaction, re-opens each wrapped row, and prints the same counts.\n")
		_, _ = fmt.Fprintf(out, "Already-wrapped member rows are skipped, so a second --confirm is a no-op.\n")
		_, _ = fmt.Fprintf(out, "--check prints a read-only leftover report.\n\n")
		_, _ = fmt.Fprintf(out, "A member row is active when status is \"active\" and expires_at is after the run time.\n")
		_, _ = fmt.Fprintf(out, "Revoked, expired, pending, and any other status are non-active, as is an active row whose expires_at is at or before the run time.\n\n")
		_, _ = fmt.Fprintf(out, "Database: MINIKMS_DB_URL\n")
		_, _ = fmt.Fprintf(out, "Root key: MINIKMS_ROOT_KEY or MINIKMS_ROOT_KEY_FILE (one source, same as the server)\n")
		_, _ = fmt.Fprintf(out, "HKDF salt: MINIKMS_HKDF_SALT when the server sets it\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, &flagBuf)
		}
		return ModeDryRun, err
	}
	if fs.NArg() != 0 {
		return ModeDryRun, fmt.Errorf("unexpected arguments")
	}
	if *check && *confirm {
		return ModeDryRun, fmt.Errorf("--check and --confirm cannot be combined")
	}
	switch {
	case *check:
		return ModeCheck, nil
	case *confirm:
		return ModeConfirm, nil
	default:
		return ModeDryRun, nil
	}
}

// Run classifies certificate rows and, in confirm mode, wraps member key material.
// Dry-run and check modes are read-only. Confirm mode uses one transaction and
// rolls it back on any failure. The report is counts only.
func Run(ctx context.Context, store Store, mgr *keys.OrgKeyManager, mode Mode, now time.Time, out io.Writer) error {
	if store == nil || mgr == nil {
		return fmt.Errorf("member key wrap is not configured")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if out == nil {
		out = io.Discard
	}

	readOnly := mode != ModeConfirm
	tx, err := store.Begin(ctx, readOnly)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if !finished {
			_ = tx.Rollback(ctx)
		}
	}()

	counted, opErr := apply(ctx, tx, mgr, mode, now)
	if opErr != nil {
		finished = true
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return rbErr
		}
		return opErr
	}
	if readOnly {
		finished = true
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return rbErr
		}
		return writeReport(out, mode, counted)
	}
	if err := tx.Commit(ctx); err != nil {
		finished = true
		_ = tx.Rollback(ctx)
		return fmt.Errorf("member key wrap commit failed: %w", err)
	}
	finished = true
	if err := writeReport(out, mode, counted); err != nil {
		return fmt.Errorf("member key wrap committed but the report could not be written: %w", err)
	}
	return nil
}

func apply(ctx context.Context, tx Tx, mgr *keys.OrgKeyManager, mode Mode, now time.Time) (tally, error) {
	var scrub secretBufs
	defer scrub.zeroize()

	rows, err := tx.ListCertificates(ctx)
	if err != nil {
		return tally{}, err
	}
	counted, jobs, cache := classify(rows, mgr, mode, now, &scrub)
	if mode != ModeConfirm {
		return counted, nil
	}
	if counted.failed > 0 {
		return counted, fmt.Errorf("%w: failed=%d", ErrClassificationFailed, counted.failed)
	}
	if len(jobs) > 0 && counted.wrapped == 0 {
		return counted, ErrNoWrappedAnchor
	}
	if err := wrapJobs(ctx, tx, jobs, cache, &scrub); err != nil {
		return counted, err
	}
	return counted, nil
}

func classify(rows []Row, mgr *keys.OrgKeyManager, mode Mode, now time.Time, scrub *secretBufs) (tally, []wrapJob, map[string][]byte) {
	var counted tally
	cache := make(map[string][]byte)
	var jobs []wrapJob
	for _, row := range rows {
		if row.CertType != certTypeMember {
			counted.skipped++
			continue
		}
		if len(row.EncryptedPrivateKey) == 0 {
			counted.empty++
			continue
		}
		orgKey, err := cachedOrgKey(mgr, cache, scrub, row.OrgID)
		if err != nil {
			counted.failed++
			continue
		}
		kind, plain := keys.ClassifyMemberKeyMaterial(orgKey, row.EncryptedPrivateKey, row.OrgID, row.SerialNumber)
		if len(plain) > 0 {
			scrub.track(plain)
		}
		active := rowActive(row.Status, row.ExpiresAt, now)
		switch kind {
		case keys.MemberKeyWrapped:
			if _, err := crypto.UnmarshalECPrivateKey(plain); err != nil {
				counted.failed++
				break
			}
			counted.addWrapped(active)
		case keys.MemberKeyRaw:
			counted.addRaw(active)
			if mode == ModeConfirm {
				scrub.track(row.EncryptedPrivateKey)
				jobs = append(jobs, wrapJob{
					id:       row.ID,
					orgID:    row.OrgID,
					serial:   row.SerialNumber,
					previous: row.EncryptedPrivateKey,
					plain:    plain,
				})
			}
		default:
			counted.failed++
		}
	}
	return counted, jobs, cache
}

func wrapJobs(ctx context.Context, tx Tx, jobs []wrapJob, cache map[string][]byte, scrub *secretBufs) error {
	for _, job := range jobs {
		orgKey, ok := cache[job.orgID]
		if !ok {
			return ErrVerifyFailed
		}
		sealed, err := crypto.Encrypt(orgKey, job.plain, []byte(keys.MemberKeyAAD(job.orgID, job.serial)))
		if err != nil {
			return fmt.Errorf("wrap member key: %w", err)
		}
		if err := tx.UpdateMemberKey(ctx, job.id, job.previous, sealed); err != nil {
			return err
		}
		stored, err := tx.ReadMemberKey(ctx, job.id)
		if err != nil {
			return err
		}
		opened, err := crypto.Decrypt(orgKey, stored, []byte(keys.MemberKeyAAD(job.orgID, job.serial)))
		if err != nil {
			crypto.ZeroizeBytes(opened)
			return ErrVerifyFailed
		}
		scrub.track(opened)
		if subtle.ConstantTimeCompare(opened, job.plain) != 1 {
			return ErrVerifyFailed
		}
	}
	return nil
}

func cachedOrgKey(mgr *keys.OrgKeyManager, cache map[string][]byte, scrub *secretBufs, orgID string) ([]byte, error) {
	if key, ok := cache[orgID]; ok {
		return key, nil
	}
	key, err := mgr.DeriveOrgKey(orgID)
	if err != nil {
		crypto.ZeroizeBytes(key)
		return nil, err
	}
	cache[orgID] = key
	scrub.track(key)
	return key, nil
}

func writeReport(out io.Writer, mode Mode, counted tally) error {
	var payload any
	if mode == ModeCheck {
		payload = counted.checkReport()
	} else {
		payload = counted.dryRunReport()
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	return enc.Encode(payload)
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
