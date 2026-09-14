# Kubernetes High-Availability Deployment

This runbook deploys miniKMS as two stateless replicas. PostgreSQL is the
durable system of record, Redis provides shared cache and rate-limit state, and
all replicas load identical cryptographic secrets from a Kubernetes Secret or
an external secret provider.

## Shared-state model

| Material | Owner | Replica requirement |
|---|---|---|
| Root encryption key | External secret manager | Identical on every replica |
| Root CA certificate and P-384 key | External secret manager | Identical on every replica |
| P-256 session-signing key | External secret manager | Identical on every replica |
| DEKs, vault entries, certificates, sessions, audit and escrow records | PostgreSQL | Shared database |
| Rate limits and cache entries | Redis | Shared instance or HA service |

Pods keep decrypted key material in memory while serving requests, but they are
never the only durable owner of critical material. Losing a pod must not lose a
key, CA, session registry entry, or vault record.

## Prerequisites

- A production PostgreSQL service reachable by every miniKMS pod.
- A production Redis service reachable by every miniKMS pod.
- The four migrations applied in order, including
  `004_multi_replica_ha.sql`.
- One 32-byte root encryption key encoded as 64 hexadecimal characters.
- One self-signed P-384 Root CA certificate/private-key pair.
- One P-256 session-signing private key.
- A secret-management mechanism such as External Secrets, Secrets Store CSI,
  or a manually created Kubernetes Secret.

Migration 004 enforces one active organization CA per organization. Inspect and
resolve duplicate active Org CA records before applying it. Org CA records from
older deployments without `encrypted_private_key` cannot be used by a new
replica; recover or reprovision those organizations during a maintenance window
before enabling multi-replica traffic.

## Provision secrets

Generate each production secret once in an approved secure environment. Do not
generate them in a pod, init container, image build, or deployment pipeline.

Create the runtime Secret from files, or configure the external-secret provider
to produce the same keys:

```sh
kubectl create secret generic minikms-runtime-secrets \
  --from-file=root-key=/secure/minikms/root-key \
  --from-file=root-ca.crt=/secure/minikms/root-ca.crt \
  --from-file=root-ca.key=/secure/minikms/root-ca.key \
  --from-file=session-signing-key.pem=/secure/minikms/session-signing-key.pem

kubectl create secret generic minikms-backend \
  --from-literal=db-url="$MINIKMS_DB_URL" \
  --from-literal=redis-url="$MINIKMS_REDIS_URL"
```

The pod mounts runtime secret files with mode `0440` and assigns them to the
pod's dedicated `fsGroup`. miniKMS permits group-read access for this Kubernetes
pattern but rejects group-writable files and any access for other users.

Never apply [secrets.example.yaml](../deploy/kubernetes/secrets.example.yaml)
with placeholder values. It documents only the required Secret keys.

## Apply migrations

Run migrations once from a controlled deployment job before updating the pods:

```sh
psql "$MINIKMS_DB_URL" -v ON_ERROR_STOP=1 -f migrations/001_initial_schema.sql
psql "$MINIKMS_DB_URL" -v ON_ERROR_STOP=1 -f migrations/002_vault_storage.sql
psql "$MINIKMS_DB_URL" -v ON_ERROR_STOP=1 -f migrations/003_escrow_recovery.sql
psql "$MINIKMS_DB_URL" -v ON_ERROR_STOP=1 -f migrations/004_multi_replica_ha.sql
```

Do not run schema migrations independently from every application replica.

## Deploy

Set the release image in
[minikms.yaml](../deploy/kubernetes/minikms.yaml), then apply it:

```sh
kubectl apply -f deploy/kubernetes/minikms.yaml
kubectl rollout status deployment/minikms
```

The Deployment starts two replicas. Its gRPC readiness and liveness probes use
the `minikms` health-service name. Startup fails before the server reports
`SERVING` if a shared secret is missing or invalid, or if PostgreSQL or Redis
cannot be reached.

No leader election is needed for normal startup because the Root CA is
externally provisioned. Organization CA creation uses a PostgreSQL advisory lock
and a unique active-CA constraint, so concurrent bootstrap requests converge on
the same durable CA.

## Rolling deployment procedure

1. Back up PostgreSQL and verify Redis and PostgreSQL health.
2. Confirm the new pods reference the existing runtime Secret. Do not generate
   replacement keys as part of a normal application rollout.
3. Apply all required migrations from a single controlled job.
4. Update the Deployment image.
5. Wait for the new pod to pass the gRPC readiness probe.
6. Verify a session issued through one replica is accepted through another.
7. Verify a KMS encrypt/decrypt and vault write/read round trip.
8. Let Kubernetes terminate one old pod. The server marks itself not serving
   and performs a graceful gRPC stop on `SIGTERM`.
9. Repeat until both replicas run the new version.
10. Review application and audit logs before declaring the rollout complete.

The Deployment uses `maxUnavailable: 0`, `maxSurge: 1`, a five-second pre-stop
drain, and a PodDisruptionBudget with `minAvailable: 1`.

## Validate two-replica behavior

The Docker E2E stack runs two miniKMS containers with identical secrets and
shared PostgreSQL/Redis:

```sh
./scripts/docker-e2e-test.sh
```

The HA client verifies all of the following:

- encrypt on replica 1 and decrypt on replica 2;
- create an Org CA on replica 1 and issue a member certificate on replica 2;
- create a managed session on replica 1;
- write a vault value through replica 1 and read it through replica 2.

After Kubernetes deployment, repeat these checks through the Service and while
restarting one pod:

```sh
kubectl delete pod <one-minikms-pod-name>
kubectl rollout status deployment/minikms
```

## Secret rotation notes

- Replacing the root encryption key without rewrapping stored keys makes
  existing ciphertext unreadable.
- Replacing the Root CA changes the trust chain and requires a planned PKI
  migration.
- Replacing the session-signing key invalidates all current sessions.
- Secret rotation is a separate coordinated operation, not part of an ordinary
  rolling deployment.
