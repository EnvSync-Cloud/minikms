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
`org_ca_wraps` are not root-key sealed and are
left unchanged. Escrow shares are sealed with the escrow seal key and are not
rewrapped. If an active root escrow set exists, the command exits without
changing data. Re-split that escrow set before running the rewrap.

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
in-scope row does not decrypt with the current root key, the command rolls
back and leaves the database unchanged.

Output is counts only: `key_versions` scanned, rewrapped, and failed;
`certificates` scanned, rewrapped, and failed per cert type; `mode=dry-run`
or `mode=commit`; and `orgs`.

After a committed run, start miniKMS with the new root key
(`MINIKMS_ROOT_KEY_FILE` or `MINIKMS_ROOT_KEY`). Keep the previous key file
until the new process is up and serving the existing data.

## Rollback

Keep the previous root key file. To return to it, stop miniKMS, restore the
database dump taken before the run, and start miniKMS with the previous root
key.
