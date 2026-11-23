package rewrap

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/keys"
)

const (
	modeDryRun = "dry-run"
	modeCommit = "commit"
)

// ErrSameRootKey is returned when the new root key matches the current one.
var ErrSameRootKey = errors.New("new root key must differ from the current root key")

// ErrConfirmRequired is returned when a writing run omits confirmation.
var ErrConfirmRequired = errors.New("real rewrap requires --dry-run=false and --confirm")

// ErrActiveRootEscrow is returned when an active root escrow set exists.
// The command does not support that deployment and leaves stored data unchanged.
// Rotating a root key that is under escrow is out of scope.
var ErrActiveRootEscrow = errors.New("active root escrow set exists; this command does not support deployments with an active root escrow set and exits without changing data; rotating a root key that is under escrow is out of scope")

// ErrCommittedReportFailed is returned when the rewrap transaction has
// committed and the count report could not be written. The write error is
// wrapped. Stored data already uses the new root key, so miniKMS must now
// be started with that key. A dry-run report failure is not this error.
var ErrCommittedReportFailed = errors.New("rewrap COMMITTED but the report could not be written; miniKMS must now be started with the new root key")

// ErrCommitOutcomeUnknown is returned when Commit itself returns an error
// on a writing run. The commit error is wrapped. The server may already
// have committed before the acknowledgement was lost, so stored data may
// or may not use the new root key. The error text is the recovery rule:
// keep miniKMS stopped, and choose the old or new key only when that
// key's dry-run check is conclusive. A check is conclusive only if it
// exits 0, reports zero failures, and scanned at least one in-scope row
// (key_versions scanned plus certificates scanned is greater than zero).
// If both checks scan zero rows, or neither is conclusive, the outcome
// stays unknown. A failed check, and a dry-run that scanned no in-scope
// rows, are not evidence that the commit did not land. Failures known to
// be before commit, including validation, decrypt failures, and update
// errors that roll back, are not this error. A dry-run does not commit
// and is not this error.
var ErrCommitOutcomeUnknown = errors.New("rewrap commit outcome is unknown; keep miniKMS stopped. " +
	"Check A: dry-run with the old key as MINIKMS_ROOT_KEY_FILE and a valid, distinct trial key " +
	"(a freshly generated 32-byte hex key in a mode-0600 file, different from both the old and new keys) as --new-key-file. " +
	"Check B: dry-run with the new key as MINIKMS_ROOT_KEY_FILE and the same valid, distinct trial key as --new-key-file. " +
	"A check is conclusive only if it exits 0, reports zero failures, and scanned at least one in-scope row (key_versions + certificates scanned > 0, printed as total scanned). " +
	"Unset MINIKMS_ROOT_KEY before either check when the key is passed in MINIKMS_ROOT_KEY_FILE. " +
	"Check A alone is not proof the commit did not land while the server can still finish it. " +
	"Repeat both checks only after that database session is gone. " +
	"Only if Check B is conclusive after that: the commit landed; start miniKMS with the new key. " +
	"Only if Check A is conclusive and Check B is not, after that session is gone: the commit did not land; keep the old key. " +
	"If that state cannot be established, or both checks scan zero rows, or neither is conclusive, the outcome stays unknown: " +
	"keep miniKMS stopped and restore from the pre-rotation DB dump with the old key (or investigate). " +
	"Delete the trial key file afterwards")

// Options configures one rewrap.
type Options struct {
	OldKey  []byte
	NewKey  []byte
	DryRun  bool
	Confirm bool
}

type counts struct {
	scanned   int
	rewrapped int
	failed    int
}

type certCounts struct {
	certType string
	counts
}

type report struct {
	mode         string
	orgs         int
	keyVersions  counts
	certificates []certCounts
}

type sealedRow struct {
	cert   bool
	id     string
	orgID  string
	aad    []byte
	plain  []byte
	sealed []byte
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

type rowOpenError struct {
	n int
}

func (e *rowOpenError) Error() string {
	return fmt.Sprintf("rewrap aborted: %d in-scope rows could not be decrypted with the current root key", e.n)
}

// Validate checks key material and commit confirmation. It does not open a database.
func Validate(opts Options) error {
	if len(opts.OldKey) != crypto.AES256KeySize || len(opts.NewKey) != crypto.AES256KeySize {
		return fmt.Errorf("root keys must be 32 bytes")
	}
	if subtle.ConstantTimeCompare(opts.OldKey, opts.NewKey) == 1 {
		return ErrSameRootKey
	}
	if !opts.DryRun && !opts.Confirm {
		return ErrConfirmRequired
	}
	return nil
}

// Run rewraps in-scope ciphertext under opts.NewKey.
// Dry-run decrypts every in-scope row and trial-encrypts with the new key
// inside a read-only transaction. A commit run updates those rows in one
// transaction, re-reads them, and verifies they decrypt with the new key
// before commit. Any error before commit rolls the transaction back.
// If Commit itself returns an error, the outcome is unknown and Run
// returns ErrCommitOutcomeUnknown. A failure to write the count report
// after a successful commit does not roll back; it returns
// ErrCommittedReportFailed.
func Run(ctx context.Context, store Store, opts Options, out io.Writer) error {
	if err := Validate(opts); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("rewrap store is required")
	}
	if out == nil {
		out = io.Discard
	}

	secrets := &secretBufs{}
	defer secrets.zeroize()

	active, err := store.HasActiveRootEscrow(ctx)
	if err != nil {
		return err
	}
	if active {
		return ErrActiveRootEscrow
	}

	tx, err := store.Begin(ctx, opts.DryRun)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if !finished {
			_ = tx.Rollback(ctx)
		}
	}()

	rep, opErr := rewrapTx(ctx, tx, opts, secrets)
	if opErr != nil {
		finished = true
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return rbErr
		}
		var opened *rowOpenError
		if errors.As(opErr, &opened) {
			if werr := writeReport(out, rep); werr != nil {
				return werr
			}
		}
		return opErr
	}

	if opts.DryRun {
		finished = true
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return rbErr
		}
		return writeReport(out, rep)
	}

	if err := tx.Commit(ctx); err != nil {
		finished = true
		// A rollback after Commit returns cannot show whether the server
		// committed before the acknowledgement was lost.
		_ = tx.Rollback(ctx)
		return fmt.Errorf("%w: %w", ErrCommitOutcomeUnknown, err)
	}
	finished = true
	if err := writeReport(out, rep); err != nil {
		return fmt.Errorf("%w: %w", ErrCommittedReportFailed, err)
	}
	return nil
}

func rewrapTx(ctx context.Context, tx Tx, opts Options, secrets *secretBufs) (report, error) {
	certTypes := OrgKeySealedCertTypes()
	keyVersions, err := tx.ListKeyVersions(ctx)
	if err != nil {
		return report{}, err
	}
	certs, err := tx.ListCertificates(ctx, certTypes)
	if err != nil {
		return report{}, err
	}
	for _, row := range certs {
		if !allowlisted(row.CertType, certTypes) {
			return report{}, fmt.Errorf("refusing certificate outside the rewrap allowlist")
		}
	}

	rep := newReport(opts.mode(), certTypes)
	orgs := make(map[string]struct{})
	oldCache := make(map[string][]byte)
	newCache := make(map[string][]byte)
	work := make([]sealedRow, 0, len(keyVersions)+len(certs))

	for _, row := range keyVersions {
		rep.keyVersions.scanned++
		noteOrg(orgs, row.OrgID)
		plain, openErr := openWith(secrets, oldCache, opts.OldKey, row.OrgID, row.EncryptedKey, dekAAD(row.OrgID))
		if openErr != nil {
			rep.keyVersions.failed++
			continue
		}
		work = append(work, sealedRow{
			id:    row.ID,
			orgID: row.OrgID,
			aad:   dekAAD(row.OrgID),
			plain: plain,
		})
	}

	for _, row := range certs {
		slot := rep.cert(row.CertType)
		if slot == nil {
			return report{}, fmt.Errorf("refusing certificate outside the rewrap allowlist")
		}
		if row.CertType == CertTypeMember && skipMemberRewrap(row.EncryptedPrivateKey) {
			continue
		}
		slot.scanned++
		noteOrg(orgs, row.OrgID)
		aad := certificateAAD(row.CertType, row.OrgID, row.SerialNumber)
		plain, openErr := openWith(secrets, oldCache, opts.OldKey, row.OrgID, row.EncryptedPrivateKey, aad)
		if openErr != nil {
			slot.failed++
			continue
		}
		work = append(work, sealedRow{
			cert:  true,
			id:    row.ID,
			orgID: row.OrgID,
			aad:   aad,
			plain: plain,
		})
	}
	rep.orgs = len(orgs)

	if n := rep.failCount(); n != 0 {
		return rep, &rowOpenError{n: n}
	}

	for i := range work {
		sealed, sealErr := reseal(secrets, newCache, opts.NewKey, work[i])
		if sealErr != nil {
			return rep, sealErr
		}
		work[i].sealed = sealed
	}

	if !opts.DryRun {
		for _, item := range work {
			if err := writeAndVerify(ctx, tx, secrets, oldCache, newCache, opts.OldKey, opts.NewKey, item); err != nil {
				return rep, err
			}
		}
	}

	rep.markRewrapped()
	return rep, nil
}

func (o Options) mode() string {
	if o.DryRun {
		return modeDryRun
	}
	return modeCommit
}

func newReport(mode string, certTypes []string) report {
	rep := report{mode: mode}
	for _, certType := range certTypes {
		rep.certificates = append(rep.certificates, certCounts{certType: certType})
	}
	return rep
}

func (r *report) cert(certType string) *certCounts {
	for i := range r.certificates {
		if r.certificates[i].certType == certType {
			return &r.certificates[i]
		}
	}
	return nil
}

func (r report) failCount() int {
	n := r.keyVersions.failed
	for _, c := range r.certificates {
		n += c.failed
	}
	return n
}

// scannedCount sums in-scope rows. The report prints it as "total scanned".
func (r report) scannedCount() int {
	n := r.keyVersions.scanned
	for _, c := range r.certificates {
		n += c.scanned
	}
	return n
}

func (r *report) markRewrapped() {
	r.keyVersions.rewrapped = r.keyVersions.scanned - r.keyVersions.failed
	for i := range r.certificates {
		r.certificates[i].rewrapped = r.certificates[i].scanned - r.certificates[i].failed
	}
}

func noteOrg(orgs map[string]struct{}, orgID string) {
	if orgID == "" {
		return
	}
	orgs[orgID] = struct{}{}
}

func allowlisted(certType string, certTypes []string) bool {
	for _, allowed := range certTypes {
		if certType == allowed {
			return true
		}
	}
	return false
}

// dekAAD matches AppDEKManager.encryptDEK / decryptDEK.
func dekAAD(orgID string) []byte {
	return []byte("dek:" + orgID)
}

// orgCAKeyAAD matches PKIService.orgCAKeyAAD.
func orgCAKeyAAD(orgID, serial string) []byte {
	return []byte("org-ca-key:" + orgID + ":" + serial)
}

func certificateAAD(certType, orgID, serial string) []byte {
	if certType == CertTypeMember {
		return []byte(keys.MemberKeyAAD(orgID, serial))
	}
	return orgCAKeyAAD(orgID, serial)
}

// skipMemberRewrap leaves empty and legacy raw member keys unchanged.
// Envelopes stay in the rewrap. A blob that is neither is a failure.
func skipMemberRewrap(blob []byte) bool {
	if len(blob) == 0 {
		return true
	}
	_, err := crypto.UnmarshalECPrivateKey(blob)
	return err == nil
}

func cachedOrgKey(secrets *secretBufs, cache map[string][]byte, root []byte, orgID string) ([]byte, error) {
	if key, ok := cache[orgID]; ok {
		return key, nil
	}
	key, err := crypto.DeriveOrgMasterKey(root, orgID)
	if err != nil {
		crypto.ZeroizeBytes(key)
		return nil, fmt.Errorf("derive organization key: %w", err)
	}
	cache[orgID] = key
	secrets.track(key)
	return key, nil
}

func openWith(secrets *secretBufs, cache map[string][]byte, root []byte, orgID string, ciphertext, aad []byte) ([]byte, error) {
	if orgID == "" || len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext could not be opened")
	}
	orgKey, err := cachedOrgKey(secrets, cache, root, orgID)
	if err != nil {
		return nil, err
	}
	plain, err := crypto.Decrypt(orgKey, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("ciphertext could not be opened")
	}
	secrets.track(plain)
	return plain, nil
}

func reseal(secrets *secretBufs, cache map[string][]byte, root []byte, item sealedRow) ([]byte, error) {
	orgKey, err := cachedOrgKey(secrets, cache, root, item.orgID)
	if err != nil {
		return nil, err
	}
	sealed, err := crypto.Encrypt(orgKey, item.plain, item.aad)
	if err != nil {
		return nil, fmt.Errorf("trial encryption failed: %w", err)
	}
	secrets.track(sealed)
	opened, err := crypto.Decrypt(orgKey, sealed, item.aad)
	if err != nil {
		return nil, fmt.Errorf("trial encryption failed: %w", err)
	}
	secrets.track(opened)
	if !sameBytes(opened, item.plain) {
		return nil, fmt.Errorf("trial encryption did not round-trip")
	}
	return sealed, nil
}

func writeAndVerify(ctx context.Context, tx Tx, secrets *secretBufs, oldCache, newCache map[string][]byte, oldRoot, newRoot []byte, item sealedRow) error {
	var err error
	if item.cert {
		err = tx.UpdateCertificate(ctx, item.id, item.sealed)
	} else {
		err = tx.UpdateKeyVersion(ctx, item.id, item.sealed)
	}
	if err != nil {
		return err
	}

	var got []byte
	if item.cert {
		got, err = tx.ReadCertificate(ctx, item.id)
	} else {
		got, err = tx.ReadKeyVersion(ctx, item.id)
	}
	if err != nil {
		return err
	}
	secrets.track(got)
	if !sameBytes(got, item.sealed) {
		return fmt.Errorf("rewritten ciphertext did not match")
	}

	newOrg, err := cachedOrgKey(secrets, newCache, newRoot, item.orgID)
	if err != nil {
		return err
	}
	opened, err := crypto.Decrypt(newOrg, got, item.aad)
	if err != nil || !sameBytes(opened, item.plain) {
		crypto.ZeroizeBytes(opened)
		return fmt.Errorf("rewritten row did not decrypt with the new root key")
	}
	secrets.track(opened)

	oldOrg, err := cachedOrgKey(secrets, oldCache, oldRoot, item.orgID)
	if err != nil {
		return err
	}
	oldPlain, err := crypto.Decrypt(oldOrg, got, item.aad)
	if err == nil {
		secrets.track(oldPlain)
		return fmt.Errorf("rewritten row still decrypts with the current root key")
	}
	return nil
}

func sameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func writeReport(w io.Writer, rep report) error {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "mode=%s orgs=%d\n", rep.mode, rep.orgs)
	_, _ = fmt.Fprintf(&b, "total scanned=%d\n", rep.scannedCount())
	_, _ = fmt.Fprintf(&b, "key_versions scanned=%d rewrapped=%d failed=%d\n",
		rep.keyVersions.scanned, rep.keyVersions.rewrapped, rep.keyVersions.failed)
	for _, c := range rep.certificates {
		_, _ = fmt.Fprintf(&b, "certificates cert_type=%s scanned=%d rewrapped=%d failed=%d\n",
			c.certType, c.scanned, c.rewrapped, c.failed)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
