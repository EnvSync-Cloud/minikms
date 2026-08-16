# Shamir Escrow Recovery Runbook

This runbook covers the audited K-of-N recovery flow for the miniKMS root key
and organization CA private keys. The default policy is 3-of-5.

## Security model

- `MINIKMS_ESCROW_SEAL_KEY` is a dedicated 256-bit key used only to encrypt
  Shamir shares at rest. It must be held in an HSM or secret manager and must
  not be derived from the root key.
- A share package is plaintext custodian material. The admin CLI creates share
  files with mode `0600`, refuses to overwrite files, and refuses recovery from
  group- or world-readable share files.
- Never place a root key, seal key, share package, or recovered key in a command
  argument, ticket, chat, log, shell history, or source repository.
- Run the CLI on a locked-down recovery host with direct PostgreSQL access.
  Transfer each share to a different custodian over an approved secure channel.
- Audit entries include the actor, set, index, custodian, threshold, and outcome.
  They never contain share bytes or recovered key material.

## Enable escrow

Apply all migrations, including the escrow-generation migration:

```sh
psql "$MINIKMS_DB_URL" -f migrations/001_initial_schema.sql
psql "$MINIKMS_DB_URL" -f migrations/002_vault_storage.sql
psql "$MINIKMS_DB_URL" -f migrations/003_escrow_recovery.sql
```

Generate the independent seal key once, store it in the deployment secret
manager, and mount it with mode `0600`:

```sh
openssl rand -hex 32 > /run/secrets/minikms-escrow-seal-key
chmod 600 /run/secrets/minikms-escrow-seal-key
```

Configure miniKMS:

```sh
export MINIKMS_ESCROW_ENABLED=true
export MINIKMS_ESCROW_SEAL_KEY_FILE=/run/secrets/minikms-escrow-seal-key
export MINIKMS_SHAMIR_TOTAL_SHARES=5
export MINIKMS_SHAMIR_THRESHOLD=3
export MINIKMS_ESCROW_CUSTODIANS=alice,bob,carol,dave,erin
```

On startup, miniKMS splits the root key immediately after unseal. Org CA keys
are split before a newly created Org CA is exposed. Restarting with the same key
is idempotent; startup fails if the active generation protects a different key,
policy, or custodian list.

Build the recovery CLI:

```sh
go build -o bin/minikms-escrow ./cmd/minikms-escrow
```

The CLI needs `MINIKMS_DB_URL` and the same escrow seal-key source as the server.

## Export and distribute shares

Export one file per custodian. Root escrow does not take an organization ID:

```sh
bin/minikms-escrow export \
  --key-type root \
  --custodian-id alice \
  --actor-id admin-123 \
  --out /secure-transfer/root-alice.share
```

For an organization CA, include its ID:

```sh
bin/minikms-escrow export \
  --key-type org_ca \
  --org-id org-123 \
  --custodian-id alice \
  --actor-id admin-123 \
  --out /secure-transfer/org-123-alice.share
```

Repeat for all configured custodians. Confirm each custodian has received and
can access only their file, then securely erase the staging copies. Record the
escrow set ID shown inside each package; all packages for one recovery must have
the same set ID.

## Perform threshold recovery

Collect at least K packages from distinct custodians onto the recovery host.
Confirm every file is mode `0600`. For a root-key recovery:

```sh
bin/minikms-escrow recover \
  --key-type root \
  --actor-id recovery-admin-123 \
  --share /recovery/alice.share \
  --share /recovery/bob.share \
  --share /recovery/carol.share \
  --out /recovery/minikms-root-key
```

The output is hex encoded and can be mounted directly on the next start:

```sh
chmod 600 /recovery/minikms-root-key
export MINIKMS_ROOT_KEY_FILE=/recovery/minikms-root-key
unset MINIKMS_ROOT_KEY
```

For an Org CA recovery:

```sh
bin/minikms-escrow recover \
  --key-type org_ca \
  --org-id org-123 \
  --actor-id recovery-admin-123 \
  --share /recovery/alice.share \
  --share /recovery/bob.share \
  --share /recovery/carol.share \
  --out /recovery/org-123-ca-key.pem
```

Recovery validates the set metadata, unique custodians and indexes, every share
hash, the configured threshold, and the reconstructed key hash. K-1 shares,
duplicates, corrupt packages, and packages from an old generation fail.

## Re-seal and clean up

A successful recovery atomically retires the recovered generation and creates a
fresh generation with the same K-of-N policy and custodians. The old packages
cannot be reused. Before leaving the recovery window:

1. Export and redistribute every share from the new generation.
2. Confirm the new set ID with each custodian.
3. Securely erase collected old shares and temporary recovered-key files after
   the restored key has been injected through the approved secret mechanism.
4. Verify the audit chain and review `escrow_recovery_succeeded` and
   `escrow_resealed` entries.

If output-file creation fails, the CLI aborts before recovery or re-sealing. If
the CLI reports a database or audit failure, stop and inspect the active set and
audit chain before retrying.

## Audit events

Expected actions are:

- `escrow_split_started`, `escrow_split_succeeded`, `escrow_split_failed`
- `escrow_set_verified`
- `escrow_share_export_started`, `escrow_share_export_succeeded`,
  `escrow_share_export_failed`
- `escrow_recovery_started`, `escrow_recovery_succeeded`,
  `escrow_recovery_failed`
- `escrow_resealed`

Root-key events use the `_root` audit scope. Org CA events use the organization
ID. Investigate any unexpected export attempt, failed integrity check, duplicate
custodian submission, or recovery outside an approved incident window.

## Existing installations

Rows created by the old placeholder escrow path have no set ID, share hash, or
reconstructed-key hash and cannot provide verified threshold recovery. Migration
003 leaves those rows unattached. After enabling escrow, create and distribute a
new generation before treating disaster recovery as operational. Remove legacy
rows only under the organization's data-retention policy.
