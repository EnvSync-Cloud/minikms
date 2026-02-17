# miniKMS

A lightweight, tenant-aware Key Management Service built in Go. miniKMS provides envelope encryption, a 3-level PKI hierarchy, and tamper-evident audit logging over gRPC.

## Why miniKMS Exists

Traditional secret management tools like HashiCorp Vault handle storage but don't provide fine-grained, per-tenant encryption key isolation. miniKMS fills this gap by offering:

- **Per-tenant key derivation** — each tenant gets an isolated master key derived via HKDF, with no shared key material between tenants
- **Per-scope DEKs** — within a tenant, each scope (application, service, environment) gets its own data encryption key
- **Envelope encryption** — data is encrypted with a DEK, and the DEK is encrypted with the tenant's master key, enabling key rotation without re-encrypting all data
- **Zero plaintext at rest** — all DEKs are stored encrypted; the root key is held only in memory

## Use Cases

- **Secret management backends** — encrypt secrets before storing them in Vault, databases, or object storage
- **Multi-tenant SaaS** — isolate encryption keys per customer/organization with automatic key provisioning
- **BYOK augmentation** — layer server-side KMS encryption on top of client-side (BYOK/PKI) encryption for defense-in-depth
- **Certificate management** — issue and manage certificates with a built-in 3-level PKI hierarchy
- **Compliance & audit** — hash-chained audit logs provide tamper-evident proof of all cryptographic operations

## Architecture

### Key Hierarchy

```
Root Key (256-bit, loaded from env at startup)
  └─ Tenant Master Key (derived via HKDF-SHA256 per tenant_id)
       └─ Scope DEK (random AES-256 key, encrypted with tenant master key)
            └─ Data (encrypted with scope DEK using AES-256-GCM)
```

- **Root Key**: A 256-bit hex-encoded key provided via `MINIKMS_ROOT_KEY` env var. Never persisted to disk.
- **Tenant Master Key**: Deterministically derived from the root key using HKDF with configurable salt. No database storage needed.
- **Scope DEK**: Random AES-256 key generated per scope. Stored encrypted (wrapped by tenant master key) in PostgreSQL with version tracking.

### Key Hierarchy & Encryption Flow

```mermaid
graph TD
    RK[Root Key<br/>256-bit, in-memory only] -->|HKDF-SHA256| TMK[Tenant Master Key<br/>per org_id, deterministic]
    TMK -->|AES-256-GCM wrap| DEK[Scope DEK<br/>per app_id, stored encrypted]
    DEK -->|AES-256-GCM + AAD| ED[Encrypted Data]
    RK -->|Shamir 3-of-5| KES[Key Escrow Shares<br/>disaster recovery]

    style RK fill:#e74c3c,color:#fff
    style TMK fill:#e67e22,color:#fff
    style DEK fill:#2ecc71,color:#fff
    style ED fill:#3498db,color:#fff
    style KES fill:#9b59b6,color:#fff
```

### PKI Certificate Chain

```mermaid
graph TD
    ROOT[Root CA<br/>P-384, self-signed<br/>MaxPathLen: 1] -->|signs| ORG[Org Intermediate CA<br/>P-384, MaxPathLen: 0<br/>OID: org_id]
    ORG -->|signs| MEMBER[Member Certificate<br/>P-256, IsCA: false<br/>ExtKeyUsage: ClientAuth<br/>OID: member_id, org_id, role]
    ORG -->|issues| CRL[CRL<br/>Certificate Revocation List]
    CRL -.->|revokes| MEMBER

    style ROOT fill:#e74c3c,color:#fff
    style ORG fill:#e67e22,color:#fff
    style MEMBER fill:#2ecc71,color:#fff
    style CRL fill:#95a5a6,color:#fff
```

### Encrypt Request Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant KMS as KMSService
    participant DEK as AppDEKManager
    participant DB as PostgreSQL
    participant OKM as OrgKeyManager
    participant RKH as RootKeyHolder
    participant Crypto as crypto

    C->>KMS: Encrypt(tenant_id, scope_id, plaintext, aad)
    KMS->>DEK: GetOrCreateDEK(tenant_id, scope_id)
    DEK->>DB: GetActiveKeyVersion()
    alt No active DEK
        DEK->>Crypto: GenerateKey()
        DEK->>OKM: DeriveOrgKey(tenant_id)
        OKM->>RKH: GetKey()
        OKM->>Crypto: DeriveOrgMasterKey(rootKey, orgID)
        DEK->>Crypto: Encrypt(orgKey, dek, aad)
        DEK->>DB: CreateKeyVersion(encryptedDEK)
    end
    DEK-->>KMS: plaintext DEK, keyVersionID
    KMS->>Crypto: Encrypt(dek, plaintext, aad)
    KMS->>DEK: IncrementAndCheckRotation(keyVersionID)
    KMS-->>C: base64(ciphertext), keyVersionID
```

### gRPC Services

| Service | Description |
|---------|-------------|
| `KMSService` | Encrypt, Decrypt, BatchEncrypt, BatchDecrypt — core envelope encryption |
| `PKIService` | 3-level certificate hierarchy: Root CA → Org Intermediate CA → Member Certificate |
| `AuditService` | Hash-chained tamper-evident audit log queries |

### Cryptographic Primitives

| Primitive | Usage |
|-----------|-------|
| AES-256-GCM | Data encryption (DEK → ciphertext) and DEK wrapping |
| HKDF-SHA256 | Root key → tenant master key derivation |
| Shamir Secret Sharing | Key escrow for disaster recovery (GF(256) arithmetic) |
| X.509 / ECDSA | PKI certificate issuance and validation |

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MINIKMS_ROOT_KEY` | Yes | — | 256-bit hex-encoded root encryption key |
| `MINIKMS_DB_URL` | Yes | — | PostgreSQL connection string |
| `MINIKMS_REDIS_URL` | Yes | — | Redis connection string (DEK caching) |
| `MINIKMS_GRPC_ADDR` | No | `0.0.0.0:50051` | gRPC listen address |
| `MINIKMS_HKDF_SALT` | No | `envsync-minikms-v1` | HKDF salt for key derivation |
| `MINIKMS_TLS_ENABLED` | No | `false` | Enable TLS for gRPC |
| `MINIKMS_TLS_CERT_FILE` | No | — | TLS certificate file path |
| `MINIKMS_TLS_KEY_FILE` | No | — | TLS private key file path |

## Deployment

### Prerequisites

- Go 1.24+
- PostgreSQL 15+
- Redis 7+

### Database Setup

Run the migration to create the required tables:

```bash
psql $MINIKMS_DB_URL -f migrations/001_initial_schema.sql
```

This creates: `key_versions`, `token_registry`, `certificates`, `crl_entries`, `kms_audit_log`, and `key_escrow_shares`.

### Run Locally

```bash
# Set required env vars
export MINIKMS_ROOT_KEY="$(openssl rand -hex 32)"
export MINIKMS_DB_URL="postgres://user:pass@localhost:5432/minikms?sslmode=disable"
export MINIKMS_REDIS_URL="redis://localhost:6379/0"

# Build and run
make build
make run
```

### Docker

```bash
# Build the image
make docker-build

# Run with docker-compose (includes PostgreSQL and Redis)
docker compose up minikms
```

The Dockerfile uses a multi-stage build (Go 1.24 builder → Alpine 3.21 runtime) and exposes port 50051.

### Docker Compose

miniKMS is included in the project's `docker-compose.yaml`:

```yaml
minikms:
  build:
    context: .
    dockerfile: Dockerfile
  ports:
    - "50051:50051"
  environment:
    MINIKMS_DB_URL: postgres://user:pass@postgres:5432/minikms?sslmode=disable
    MINIKMS_REDIS_URL: redis://redis:6379/1
    MINIKMS_ROOT_KEY: ${MINIKMS_ROOT_KEY}
    MINIKMS_GRPC_ADDR: 0.0.0.0:50051
  depends_on:
    - postgres
    - redis
```

## API Reference

### KMSService

#### Encrypt

Encrypt a plaintext value with the scope's DEK. Automatically provisions a DEK if one doesn't exist for the tenant/scope pair.

```protobuf
rpc Encrypt(EncryptRequest) returns (EncryptResponse);

message EncryptRequest {
    string tenant_id = 1;   // Tenant identifier
    string scope_id = 2;    // Scope/namespace identifier
    bytes plaintext = 3;
    string aad = 4;         // Additional Authenticated Data
}

message EncryptResponse {
    bytes ciphertext = 1;
    string key_version_id = 2;
}
```

#### Decrypt

```protobuf
rpc Decrypt(DecryptRequest) returns (DecryptResponse);

message DecryptRequest {
    string tenant_id = 1;
    string scope_id = 2;
    bytes ciphertext = 3;
    string aad = 4;
    string key_version_id = 5;
}
```

#### BatchEncrypt / BatchDecrypt

Encrypt or decrypt multiple items in a single call for better throughput.

### PKIService

3-level certificate hierarchy:

1. **Root CA** — self-signed, long-lived
2. **Org Intermediate CA** — per-tenant, signed by Root CA
3. **Member Certificate** — per-user/service, signed by Org CA

### AuditService

Query hash-chained audit log entries. Each entry contains:

```
entry_hash = SHA256(previous_hash || timestamp || action || actor_id || details)
```

This provides tamper-evidence: modifying any historical entry breaks the hash chain.

## Development

```bash
# Build
make build

# Run tests
make test

# Regenerate protobuf code
make proto

# Build Docker image
make docker-build
```

### Project Structure

```
minikms/
├── api/proto/minikms/v1/   # Protobuf service definitions
│   ├── kms.proto           # KMS encrypt/decrypt service
│   ├── pki.proto           # PKI certificate service
│   └── audit.proto         # Audit log service
├── cmd/minikms/            # Application entrypoint
│   └── main.go
├── internal/
│   ├── config/             # Environment-based configuration
│   ├── crypto/             # Cryptographic primitives
│   │   ├── aes256gcm.go    # AES-256-GCM encrypt/decrypt
│   │   ├── hkdf.go         # HKDF key derivation
│   │   └── shamir.go       # Shamir Secret Sharing (GF(256))
│   ├── keys/               # Key management
│   │   ├── root_key.go     # Singleton root key holder
│   │   ├── org_key.go      # HKDF-derived tenant master keys
│   │   └── app_dek.go      # Per-scope DEK lifecycle
│   ├── service/            # gRPC service implementations
│   │   ├── kms_service.go  # KMS encrypt/decrypt handlers
│   │   └── key_service.go  # Key provisioning handlers
│   └── store/              # Data access layer
│       └── postgres.go     # PostgreSQL key_versions queries
├── migrations/
│   └── 001_initial_schema.sql
├── Dockerfile
├── Makefile
└── go.mod
```

## Security Considerations

- The **root key** is the most sensitive piece of data. It should be injected via a secure mechanism (e.g., Kubernetes secrets, cloud KMS unsealing) and never written to disk or logs.
- **HKDF salt** should be consistent across deployments. Changing it will make existing tenant master keys underivable.
- **Key rotation**: New DEK versions can be created per scope. Old versions remain available for decryption via `key_version_id`. Encrypt operations always use the latest version.
- **Shamir Secret Sharing** enables splitting the root key into N shares with a threshold of K for disaster recovery.
