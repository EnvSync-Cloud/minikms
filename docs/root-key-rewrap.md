# Root key rewrap

`minikms-rewrap` re-seals data protected by organization master keys derived
from the miniKMS root key. Each in-scope row is decrypted with the current
root key and encrypted with the new root key, using the same associated data
as the server. Stop miniKMS before a real run, and start it again with the
new root key after the command commits.

## Scope

The command reads and updates:

- `key_versions.encrypted_key` for every row, including retired versions.
  The associated data is `dek:<org_id>`.
- `certificates.encrypted_private_key` where `cert_type` is
  `org_intermediate_ca`. That value is the allowlist. Active organization
  intermediate CAs, pending organization CA CSRs, and environment CAs are
  stored with this cert type. The associated data is
  `org-ca-key:<org_id>:<serial_number>`.

Certificate rows whose `cert_type` is not on that allowlist are not read or
updated. A null `encrypted_private_key` is not in scope. `vault_entries` and
`org_ca_wraps` are not root-key sealed and are left unchanged. Escrow shares
are sealed with the escrow seal key and are not rewrapped. This command does
not support deployments with an active root escrow set. If one exists, the
command exits without changing data. Rotating a root key that is under escrow
is out of scope for this command.

`MINIKMS_HKDF_SALT` must match the server. When it is unset, the command uses
the server default. The database must already include `key_escrow_sets` so the
active-set check can run. If that check cannot be completed, the command stops
without writing.

## Keys and database

The current root key uses the server sources. Set one of
`MINIKMS_ROOT_KEY_FILE` or `MINIKMS_ROOT_KEY`.

The new root key is read only from `--new-key-file`. The file must already
exist, contain a 32-byte hex key, and pass the same permission check as
`MINIKMS_ROOT_KEY_FILE`. Create it with mode `0600`. Do not pass the new key
as a flag value or an environment variable.

The database URL is `MINIKMS_DB_URL`.

## Dry run

Dry-run is the default. It opens a read-only transaction, decrypts every
in-scope row with the current root key, trial-encrypts with the new key in
memory, and prints counts. It does not write. In this mode the rewrapped
count is the number of rows that would be rewritten.

```sh
export MINIKMS_DB_URL='postgres://minikms@127.0.0.1:5432/minikms?sslmode=disable'
export MINIKMS_ROOT_KEY_FILE=/run/secrets/minikms-root-key

bin/minikms-rewrap --new-key-file /run/secrets/minikms-root-key.new
```

Example output:

```text
mode=dry-run orgs=2
total scanned=7
key_versions scanned=4 rewrapped=4 failed=0
certificates cert_type=org_intermediate_ca scanned=3 rewrapped=3 failed=0
```

A real run requires both flags. Stop miniKMS first. Take a database dump
before continuing.

```sh
bin/minikms-rewrap \
  --new-key-file /run/secrets/minikms-root-key.new \
  --dry-run=false \
  --confirm
```

The real run uses one transaction. It rewraps the in-scope rows and reads
them back to confirm they decrypt with the new root key before commit. If any
in-scope row does not decrypt with the current root key, or any other error
occurs before commit, the command rolls back and leaves the database
unchanged. A failure to write the count report after commit does not roll
back. If Commit itself returns an error, the outcome is unknown: the server
may have committed before the acknowledgement was lost.

Output is counts only: `total scanned` (the sum of `key_versions` scanned
and `certificates` scanned); `key_versions` scanned, rewrapped, and failed;
`certificates` scanned, rewrapped, and failed per cert type; `mode=dry-run`
or `mode=commit`; and `orgs`. No key material is printed.

After a committed run, start miniKMS with the new root key
(`MINIKMS_ROOT_KEY_FILE` or `MINIKMS_ROOT_KEY`). Keep the previous key file
until the new process is up and serving the existing data.

Exit status 0 means the report was written. Exit status 1 means the rewrap
was not committed. That includes validation failures, decrypt failures,
update errors that roll the transaction back, and a dry-run whose report
could not be written. Exit status 3 means the rewrap committed and the count
report could not be written. The command prints that on stderr. miniKMS must
now be started with the new root key. Exit status 4 means the commit outcome
is unknown. Commit itself returned an error, and the server may have
committed before the acknowledgement was lost. Keep miniKMS stopped.

Determine the state with two dry-runs. Use a valid, distinct trial key: a
freshly generated 32-byte hex key in a mode-0600 file, different from both
the old and new keys. Delete the trial key file afterwards.

A check is conclusive only if it exits 0, reports zero failures, and scanned
at least one in-scope row (`key_versions` scanned plus `certificates` scanned
is greater than 0). The report prints that sum as `total scanned`. Exit 0
with zero failures and `total scanned=0` proves nothing: both keys can
dry-run cleanly when no in-scope rows exist.

Check A: dry-run with the old key as `MINIKMS_ROOT_KEY_FILE` and that trial
key as `--new-key-file`. Only if Check A is conclusive, the commit did not
land; keep the old key.

Check B: dry-run with the new key as `MINIKMS_ROOT_KEY_FILE` and the same
valid, distinct trial key as `--new-key-file`. Only if Check B is conclusive,
the commit landed; start miniKMS with the new key.

If both checks scan zero rows, or neither is conclusive, the outcome stays
unknown. Keep miniKMS stopped and restore from the pre-rotation DB dump with
the old key (or investigate). The rollback section describes restoring that
dump.

## Rollback

Keep the previous root key file. To return to it, stop miniKMS, restore the
database dump taken before the run, and start miniKMS with the previous root
key.
