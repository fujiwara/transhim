# transhim — Design Document

> A Go framework for building HashiCorp Vault Transit–compatible API servers whose actual cryptography is delegated to user-supplied backends (typically a cloud KMS).

Status: Draft v0.3 (M0 capture results applied, see [compat.md](compat.md); M1–M4 implemented: v1 is accepted against Ceph 18.2.8, 19.2.7, and 20.2.5)
Audience: implementers (including coding agents) and reviewers

---

## 1. Background

Several pieces of software can use HashiCorp Vault's Transit secrets engine as a key-management service. The most important one for this project is Ceph RGW (SSE-KMS and SSE-S3). Many operators, however, want their key material to live in a cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault, domestic cloud KMS services, HSM-backed services, etc.) rather than in Vault.

These cloud KMS services expose roughly the same primitive, "encrypt/decrypt this small blob with key ID X". The client software, however, only speaks the Vault Transit HTTP API.

**transhim** fills that gap. It is a library that:

1. Serves the subset of the Vault Transit HTTP API that real clients use.
2. Translates each call into a small Go interface that the user implements against their KMS of choice.
3. Handles the cross-cutting concerns once, correctly: ciphertext envelope format, authentication hooks, decrypt caching, audit, error mapping, and an optional key hierarchy for per-bucket keys.

The name means "**tran**sit **shim**".

---

## 2. Goals

- G1. Be a drop-in replacement for Vault Transit for **Ceph RGW SSE-KMS and SSE-S3**, using the "new style" (datakey-based) transit mode.
- G2. Make the user-facing extension point small. A user should only need to implement `Encrypt` and `Decrypt` against their KMS to get a working server.
- G3. Provide the `encrypt` endpoint. RGW may never call it, but every other Transit client needs it (see §4), so it is part of v1. It is the **only** v1 endpoint that is not driven by RGW.
- G4. Correct-by-default security. The ciphertext is bound to the key name and context. The decrypt cache is safe. Plaintext keys are never logged.
- G5. Keep the core free of third-party dependencies: the standard library and `golang.org/x` only. Cloud SDKs live only in examples or separate modules.
- G6. Be testable without any cloud account. Provide an in-memory fake backend and a conformance test suite.

### v1 scope rule

**v1 is done when Ceph RGW SSE-KMS and SSE-S3 work.** v1 implements exactly the endpoints that RGW calls, plus `encrypt`. Anything that exists only for other clients is deferred (§3, D6–D9). If the M0 capture (§15) shows that RGW calls an endpoint listed as deferred, that endpoint moves back into v1.

## 3. Non-Goals (explicitly out of scope)

The implementer **must not** build these in v1:

- NG1. A general Vault replacement. No KV engine, PKI, database secrets, identity, or policies language.
- NG2. Vault auth methods other than a static-token hook. No AppRole, Kubernetes, JWT/OIDC, or userpass login endpoints.
- NG3. The legacy transit key export (`/export/encryption-key/...`). Cloud KMS keys are non-exportable by design, and exporting defeats the purpose.
- NG4. Transit features unrelated to key wrapping: `hmac`, `sign`, `verify`, `hash`, `random`, `backup`, `restore`, `trim`, key import (BYOK), convergent encryption, and asymmetric key types.
- NG5. Implementing the cloud KMS clients themselves in the core module.
- NG6. A standalone binary with its own config file format in v1. Users write their own `main`. One example `main` is provided (see §11).
- NG7. Vault Enterprise namespace semantics. The `X-Vault-Namespace` header is passed to the authorizer as data and otherwise ignored.
- NG8. Vault Agent emulation, response wrapping, and the Vault UI.
- NG9. Clustering or replication of transhim state. Statelessness is preferred. The only state is the optional KeyStore (§8), which the user provides.

Deferred to later versions (may be added later; do not implement now):

- D1. `rewrap` endpoint.
- D2. `batch_input` on encrypt/decrypt.
- D3. `datakey/wrapped` (ciphertext-only datakey).
- D4. Key rotation endpoints (`keys/{name}/rotate`).
- D5. Built-in Prometheus metrics. v1 exposes hooks only.
- D6. Token stubs `auth/token/lookup-self` and `renew-self` (§6.7). Only go-kms-wrapping–based clients need them.
- D7. `GET keys/{name}` (§6.5) and the `KeyDescriber` interface. RGW is not expected to read key metadata.
- D8. `GET /v1/sys/health` (§6.7). Users write their own `main` and can add a health handler to their mux.
- D9. Verification and support claims for any client other than RGW (UC3–UC5).

---

## 4. Use Cases

### UC1. Ceph RGW SSE-KMS (primary)

The client sends `x-amz-server-side-encryption: aws:kms` with a key ID. RGW calls:

- `POST {prefix}/datakey/plaintext/{key_name}` on write
- `POST {prefix}/decrypt/{key_name}` on read

`key_name` is the client-supplied key ID. The user's backend maps it to a cloud KMS key (directly, via alias, or via a lookup table). It may also decide whether the caller is allowed to use that key.

RGW config (reference): `rgw_crypt_s3_kms_backend = vault`, `rgw_crypt_vault_secret_engine = transit`, `rgw_crypt_vault_addr`, `rgw_crypt_vault_prefix`, `rgw_crypt_vault_auth = token`, `rgw_crypt_vault_token_file`. No `compat` option is needed: unless the prefix ends with `/export/encryption-key`, RGW defaults to the new datakey-based API only (verified, compat.md).

RGW always sends a `context` (base64 of a JSON object holding the object's ARN) and repeats it unchanged on decrypt. It rejects key IDs containing `/` by itself.

### UC2. Ceph RGW SSE-S3 (primary)

RGW manages one key per bucket. The key name comes from `rgw_crypt_sse_s3_key_template` (default `%bucket_id`, which expands to the bucket marker). Besides datakey/decrypt, RGW calls:

- `POST {prefix}/keys/{key_name}` with `{"type":"chacha20-poly1305","derived":true}` on the first encrypted write to a bucket, always before the first `datakey` call
- `POST {prefix}/keys/{key_name}/config` with `{"deletion_allowed": true}` before deletion
- `DELETE {prefix}/keys/{key_name}` when the bucket is removed

Verified behavior that shapes the design (compat.md):

- RGW before tentacle sends the `DELETE` only if the `config` response has **no body**. A real Vault or OpenBao answers with key metadata, so those releases never delete bucket keys there. transhim answers with an empty 204 and gets the `DELETE` on every release.
- `DeleteBucketEncryption` makes RGW forget the bucket key without deleting it. A later SSE-S3 write calls `POST keys/` again with the same name, so creation must keep the existing key. If the bucket is deleted in that state, the key is never deleted.

Creating one cloud KMS key per bucket is usually too expensive and too slow. transhim therefore ships an optional **hierarchical backend** (§8). It keeps one root key in the cloud KMS and one wrapped intermediate key per bucket in a user-provided store. Deleting the bucket key deletes the intermediate key, which achieves crypto-shredding. This is best effort: as described above, RGW does not always send the delete, so orphaned intermediate keys are possible.

UC3–UC5 below are **not v1 targets**. They are listed to explain why `encrypt` exists and what the deferred items (D6–D9) are for. v1 neither verifies nor claims support for them.

### UC3. OpenTofu state encryption (future)

The `openbao` key provider uses `datakey/plaintext` and `decrypt`, and may read `keys/{name}`.

### UC4. Key-wrapping clients using `encrypt`/`decrypt` (future)

- Vault / OpenBao transit auto-unseal (`seal "transit"`)
- Nomad `keyring "transit"`
- Boundary `kms "transit"`
- SOPS (`hc_vault_transit`)
- Pulumi `hashivault://` secrets provider

Most of these use the go-kms-wrapping transit wrapper. That wrapper may call token `lookup-self` / `renew-self` (see §6.7).

### UC5. RustFS (future, unverified)

RustFS has a `vault-transit` KMS backend. The exact endpoint set is **unknown** and must be captured before support is claimed (see §12).

---

## 5. Architecture

```
          client (RGW, OpenTofu, Nomad, ...)
                     │  Vault Transit HTTP API
                     ▼
┌──────────────────────────────────────────────────────┐
│ transhim.Server (http.Handler)                       │
│  ├─ router: mount prefix → Mount                     │
│  ├─ authn/authz hook                                 │
│  ├─ request decoding / Vault-style error encoding    │
│  ├─ ciphertext envelope (vault:vN:...)               │
│  ├─ decrypt cache                                    │
│  └─ audit hook                                       │
└──────────────┬───────────────────────────────────────┘
               │ Go interfaces
       ┌───────┴──────────────┐
       ▼                      ▼
 user Backend          HierarchicalBackend (optional, in-core)
 (cloud KMS)              ├─ root: user Backend
                          └─ KeyStore (user-provided)
```

### Package layout

```
transhim/                 core (stdlib and golang.org/x only)
  server.go               Server, options, routing, handlers
  mount.go
  auth.go                 Authorizer, AuthRequest
  backend.go              Backend interfaces & request/response types
  envelope.go             ciphertext encoding/decoding
  cache.go                decrypt cache
  errors.go               error types & HTTP mapping
  audit.go
  hierarchical/           HierarchicalBackend + KeyStore interface
  transhimtest/           in-memory fake backend, conformance suite, Vault fixture tests
  keystore/memstore/      in-memory KeyStore (tests & dev only)
examples/
  awskms/                 separate go.mod; AWS KMS backend + example main
  gcpkms/                 separate go.mod (optional, later)
```

Go version: the two latest stable Go releases (1.26 and 1.27 at implementation time). Module path: `github.com/fujiwara/transhim`.

---

## 6. HTTP API Specification

General rules:

- All endpoints live under a **mount prefix**, for example `/v1/transit`. The prefix is configured per mount, and the client's `*_prefix` setting must match it. Prefixes are normalized: there is a single leading `/` and no trailing `/`.
- The prefix is used **only for HTTP routing**. Everything past the router (backend calls, authorizer, audit, cache, KeyStore) identifies the mount by its **mount ID** (§7.2), never by its prefix.
- Requests and responses use JSON. Responses follow Vault's envelope: `{"request_id": "...", "data": {...}, ...}`. Only `data` is required by known clients. `request_id` is a random UUID. Other top-level fields (`lease_id`, `renewable`, `lease_duration`, `wrap_info`, `warnings`, `auth`) are emitted with zero values for safety.
- Errors use `{"errors": ["message"]}` with an HTTP status code (§6.8).
- Both `POST` and `PUT` are accepted wherever Vault accepts them as writes. RGW only uses `POST` and `DELETE`.
- Request bodies are parsed as JSON **regardless of `Content-Type`**: RGW sends none. An empty body is treated as `{}`.
- `X-Vault-Token` may appear more than once (RGW sends it twice with the same value). The first value is used.
- **Key name** is everything after the operation segment. It is URL-unescaped once and treated as an **opaque string**. It must allow `.`, `-`, `_`, and `$` (RGW tenant user IDs). It is rejected if it is empty, contains `/`, or contains control characters.
- Unknown paths under a mount return 404 and are logged at WARN, so that client API drift is noticed.
- Request bodies are limited, with a default of 1 MiB (configurable). A larger body is answered with 413.
- Any method other than `POST` and `PUT` on a known operation is answered with 405, as Vault does.
- Checks run in this order: route (404), method (405), key name (400), authorizer, body. A denied request never reaches the backend.

### 6.1 `POST {prefix}/datakey/plaintext/{name}`

Request fields:

| field | type | notes |
|---|---|---|
| `context` | base64 string, optional | bound as AAD (§7.2) |
| `bits` | int, optional | 128, 256 (default), or 512, matching Vault. Return 400 for any other value. |
| `nonce` | ignored | |

Response `data`:

| field | type |
|---|---|
| `plaintext` | base64 of a random data key of `bits/8` bytes |
| `ciphertext` | envelope string (§7.1) |
| `key_version` | int |

Behavior: if the backend implements `DataKeyGenerator`, use it. Otherwise generate the key with `crypto/rand` and call `Backend.Encrypt`.

### 6.2 `POST {prefix}/encrypt/{name}`

RGW may not call this endpoint. It is in v1 because other Transit clients cannot work without it (G3). It is covered by the conformance suite, not by the RGW integration test.

Request: `plaintext` (base64, required), `context` (base64, optional), `key_version` (ignored with a warning in v1).
Response `data`: `ciphertext`, `key_version`.

Plaintext size limit: configurable per mount, default 4096 bytes after decoding. Return 400 if it is exceeded. This exists because many cloud KMS Encrypt APIs cap at 4 KiB.

Vault auto-creates keys on `encrypt` when the policy allows it. transhim does **not** do this. If the backend reports the key as not found, the request fails.

### 6.3 `POST {prefix}/decrypt/{name}`

Request: `ciphertext` (envelope, required), `context` (base64, optional).
Response `data`: `plaintext` (base64).

Behavior: decode the envelope. Verify that the key name and context binding match (§7.2). Consult the cache (§9). Otherwise call `Backend.Decrypt`.

### 6.4 `POST {prefix}/keys/{name}` (create)

The body may contain `type`, `exportable`, `derived`, etc. These are ignored, except that `exportable: true` is **rejected** with 400.

- If the backend implements `KeyLifecycle`, call `CreateKey`. It must be idempotent: an existing key returns success.
- Otherwise, return 204 without doing anything. Keys are assumed to be pre-provisioned in the KMS. This is configurable: the mount option `RejectUnmanagedKeyOps` returns 405 instead, for create, config, and delete alike.

Response: 204 No Content with an **empty body**. This is deliberate and differs from Vault and OpenBao, which answer 200 with the key's metadata: RGW expects an empty response here and logs an error otherwise (compat.md).

Creating a key that already exists must leave the existing key untouched and succeed. RGW relies on this after `DeleteBucketEncryption` (§4, UC2).

### 6.5 `GET {prefix}/keys/{name}` (read) — deferred (D7), not in v1

In v1 this path returns 404 like any unknown path. The specification below is kept for the later version.

This is minimal metadata for clients that check whether a key exists.

Response `data`: `name`, `type` (`"aes256-gcm96"`), `latest_version`, `min_decryption_version: 1`, `min_encryption_version: 0`, `deletion_allowed`, `exportable: false`, `derived: false`, `supports_encryption: true`, `supports_decryption: true`, `supports_derivation: false`, `supports_signing: false`, and `keys: {"1": <unix time>}`.

If the backend implements `KeyDescriber`, use its information. Otherwise, report existence as "unknown, assume exists" with version 1.

### 6.6 `POST {prefix}/keys/{name}/config` and `DELETE {prefix}/keys/{name}`

- `config`: accept `deletion_allowed` (bool) and ignore all other fields. Record `deletion_allowed` in memory per `(mount_id, name)` (it is a best-effort safety latch; it does not need to be durable). It is only recorded on mounts with `RequireDeletionAllowed`, the only place where it is read, and dropped when the key is deleted. Respond 204 with an **empty body**. This is required, not cosmetic: RGW before tentacle treats a non-empty `config` response as a failure and then never sends the `DELETE` (compat.md). `config` on a key the backend does not know also answers 204, since transhim cannot tell in general.
- `DELETE`: if the backend implements `KeyLifecycle`, call `DeleteKey`. Deletion is idempotent: a missing key returns success. Then **invalidate all cache entries** for that `(mount_id, name)`. Without `KeyLifecycle`, respond 204 without calling the backend (or 405 if `RejectUnmanagedKeyOps` is set); the cache entries are invalidated all the same, since the key may have been removed in the KMS.
- `GET keys/{name}` answers 404 (D7). Other methods on `keys/...` answer 405.
- Mount option `RequireDeletionAllowed` (default false) rejects DELETE with 400 unless `config` was called first. It defaults to false because transhim may restart between the two calls.

### 6.7 Token stubs and health — deferred (D6, D8), not in v1

In v1 the server serves nothing outside its mounts. The specification below is kept for the later version.

Token stubs (outside mounts, under `/v1/auth/token/`) exist for go-kms-wrapping–based clients:

- `GET /v1/auth/token/lookup-self`: runs the authorizer with op `token_lookup`. On success, returns `data` with `renewable: false`, `ttl: 0`, `expire_time: null`, `policies: ["default"]`, and `type: "service"`.
- `POST /v1/auth/token/renew-self`: returns an `auth` block with `renewable: false` and `lease_duration: 0`.

These stubs are disabled by default and enabled with `WithTokenStubs()`. **The implementer must verify** against the go-kms-wrapping source that `renewable: false` stops its renewal loop cleanly.

`GET /v1/sys/health` returns 200 `{"initialized":true,"sealed":false,"standby":false}`. It is always enabled and requires no auth.

### 6.8 Error mapping

| Go error (from backend or core) | HTTP | message |
|---|---|---|
| `ErrInvalidRequest` / malformed JSON / bad base64 | 400 | descriptive |
| `ErrKeyNotFound` | 400 | `encryption key not found` (verified against OpenBao for `datakey` and `decrypt`) |
| `ErrCiphertextMismatch` (wrong key name / context / tampered) | 400 | `invalid ciphertext` (no detail) |
| `ErrPermissionDenied` | 403 | `permission denied` |
| unknown path | 404 | |
| `ErrUpstream` (KMS unavailable, throttled) | 502 (or 503 if `Retryable`) | `upstream key service error` |
| anything else | 500 | `internal error` |

Upstream error details go to logs and audit only, never into the response body.

---

## 7. Ciphertext and Binding

### 7.1 Envelope format

The external form is `vault:v{N}:{base64std(payload)}`.

- `N` is the key version reported by the backend (default 1). Some clients parse it.
- Only the canonical encoding is accepted on decrypt (strict base64, minimal varints, no trailing bytes), so a ciphertext has exactly one string form.
- `payload` is transhim's binary envelope:

```
byte    format version (0x01)
byte    flags (reserved, 0)
uvarint len(keyRef) | keyRef bytes     // backend-opaque reference to the exact KMS key/version used
uvarint len(blob)   | blob bytes       // backend-produced ciphertext
```

The backend never sees the envelope. It receives and returns `WrappedKey{KeyRef string, Blob []byte, Version int}`.

### 7.2 Binding to key name and context

Every backend call receives an `AAD` value computed by the core:

```
AAD = "transhim/v1" || 0x00 || mount_id || 0x00 || key_name || 0x00 || context_bytes
```

Backends **must** cryptographically bind AAD. For example, they can pass it as the AWS KMS EncryptionContext (a single entry holding `hex(sha256(AAD))`, see §11), as GCP KMS `additionalAuthenticatedData`, or as AES-GCM AAD. Then a ciphertext produced for `(mount_id, name, context)` cannot be decrypted under a different triple, even if the cache is bypassed.

`mount_id` is a stable string that identifies a mount independently of its prefix:

- It is **required** for every mount. There is no default, and in particular it is never derived from the prefix. This keeps the prefix free to change (for example to match a client's `*_prefix` setting) without affecting existing ciphertexts.
- It must be non-empty, must not contain NUL or other control characters (NUL is the AAD separator), and must be unique among the mounts of a server. `NewServer` returns an error otherwise.
- It is the only mount identifier visible outside the router. Every `MountID` field and `mountID` parameter in §8, the cache key (§9), and the audit event (§10) carry this value.
- Changing it breaks decryption of existing data (and, with the hierarchical backend, lookup of stored intermediate keys). This must be documented loudly.

### 7.3 Context semantics

- An absent context and an empty context are equivalent.
- A context supplied on encrypt must be supplied identically on decrypt.
- Vault only uses the context for derived keys and silently ignores it for other keys (verified: a ciphertext made with a context decrypts without it). transhim binds it whenever it is present. This is stricter, and compatible with RGW, which always sends the same context for an object on write and on read (verified).

---

## 8. Go Interfaces (core contract)

Names are indicative. The implementer may adjust them but must keep the semantics.

```go
type Backend interface {
    Encrypt(ctx context.Context, req EncryptRequest) (WrappedKey, error)
    Decrypt(ctx context.Context, req DecryptRequest) ([]byte, error)
}

type EncryptRequest struct {
    MountID   string // mount ID (§7.2), not the prefix
    KeyName   string
    Plaintext []byte
    AAD       []byte
}

type DecryptRequest struct {
    MountID string
    KeyName string
    Wrapped WrappedKey
    AAD     []byte
}

type WrappedKey struct {
    KeyRef  string // opaque; returned on encrypt, given back on decrypt
    Version int    // >=1; exposed as vault:vN
    Blob    []byte
}

// Optional capabilities, discovered via type assertion.
type DataKeyGenerator interface {
    GenerateDataKey(ctx context.Context, req DataKeyRequest) (plaintext []byte, wk WrappedKey, err error)
}
type KeyLifecycle interface {
    CreateKey(ctx context.Context, mountID, keyName string) error // idempotent
    DeleteKey(ctx context.Context, mountID, keyName string) error // idempotent
}
// Deferred (D7), not in v1.
type KeyDescriber interface {
    DescribeKey(ctx context.Context, mountID, keyName string) (KeyInfo, error)
}
```

Backends never receive the mount prefix. `DataKeyRequest` likewise carries `MountID`.

Server construction (functional options):

```go
srv, err := transhim.NewServer(
    transhim.Mount("/v1/transit", "rgw-kms", backend), // prefix, mount ID (required), backend
    transhim.WithAuthorizer(fn),          // func(ctx, AuthRequest) error
    transhim.WithDecryptCache(cfg),
    transhim.WithAuditHook(fn),
    transhim.WithLogger(*slog.Logger),
)
// srv implements http.Handler
```

The mount ID is a positional argument of `Mount` rather than an option, so that omitting it is a compile error. `NewServer` validates it as described in §7.2.

`AuthRequest` contains: `Op` (`datakey|encrypt|decrypt|key_create|key_config|key_delete` in v1; `key_read`, `token_lookup`, and `token_renew` arrive with D6/D7), `MountID`, `KeyName`, `Token` (from `X-Vault-Token`), `Namespace` (from `X-Vault-Namespace`), `TLS` (`*tls.ConnectionState`), and `RemoteAddr`. If no authorizer is configured, `NewServer` returns an error unless `transhim.AllowUnauthenticated()` is passed explicitly.

The authorizer returns an error wrapping `ErrPermissionDenied` to answer 403. Any other error also rejects the request and is mapped as in §6.8. `transhim.StaticTokenAuthorizer(token)` is provided for the common single-token setup (constant-time comparison; an empty token allows nothing).

`ErrUpstream` is a sentinel. `*UpstreamError{Err, Retryable}` matches it and selects 503 when `Retryable` is set.

### Hierarchical backend (`transhim/hierarchical`)

This is for UC2 (per-bucket keys without per-bucket cloud keys).

```go
type KeyStore interface {
    Get(ctx context.Context, mountID, keyName string) (StoredKey, error) // ErrKeyNotFound if absent
    PutIfAbsent(ctx context.Context, mountID, keyName string, k StoredKey) error // ErrKeyExists if present
    Delete(ctx context.Context, mountID, keyName string) error            // idempotent
}
type StoredKey struct {
    Wrapped   transhim.WrappedKey // intermediate key, wrapped by the root backend
    CreatedAt time.Time
}

func New(root transhim.Backend, rootKeyName string, store KeyStore, opts ...Option) (*Backend, error)
```

`PutIfAbsent` must be atomic. If a key already exists for `(mountID, keyName)`, it must leave the stored key untouched and return `ErrKeyExists`. The KeyStore has no listing method in v1; if one is needed later (admin CLI, garbage collection of orphaned keys), it will be added as a separate optional interface.

Root key usage:

- `rootKeyName` is the fixed key name that the hierarchical backend passes to the root backend. The per-bucket key name is **never** passed to the root backend as `KeyName`; it only appears in the AAD.
- Root calls use `EncryptRequest{MountID: mountID, KeyName: rootKeyName, Plaintext: intermediateKey, AAD: rootAAD}` (and the matching `DecryptRequest`), where

  ```
  rootAAD = "transhim/hierarchical/v1" || 0x00 || mount_id || 0x00 || key_name
  ```

  The distinct prefix separates it from the core AAD (§7.2), so a wrapped intermediate key can never be presented as an ordinary ciphertext or vice versa. `rootAAD` and `rootKeyName` are part of the on-disk compatibility contract, like `mount_id`.

Behavior:

- `CreateKey`: look the key up in the KeyStore first and return success if it exists, without a root call (RGW re-creates existing keys after `DeleteBucketEncryption`). Otherwise generate a 32-byte intermediate key, wrap it with root `Encrypt` as described above, and call `PutIfAbsent`. On `ErrKeyExists`, discard the generated key and return success (the existing key wins). This makes `CreateKey` idempotent and safe under concurrent creation.
- `Encrypt`/`Decrypt`: load and unwrap the intermediate key, then apply AES-256-GCM locally with a random 12-byte nonce, `Blob = nonce || ct`, and the AAD from the core. `KeyRef` is set to `"h1"`.
- Unwrapped intermediate keys are cached in memory, keyed by `(mountID, keyName)`, with their own TTL (`WithKeyCacheTTL`, default 5 minutes, 0 disables). They are evicted on `DeleteKey`, also when the KeyStore reports a failure. A key that was being loaded while a deletion happened is not cached. A key that `CreateKey` just stored is cached, so the `datakey` call that RGW sends next needs no root call.
- Concurrent loads of the same intermediate key (first use, or after its cache entry expired) are merged into one KeyStore read and one root call, for the same reason and with the same cancellation rule as in §9.
- Root backend errors are passed on only if they are `ErrUpstream`, `ErrPermissionDenied`, or a context error. Anything else (the root key is missing, a stored key does not unwrap) becomes an internal error: it is not the client's key or ciphertext that is wrong.
- `DeleteKey`: delete from the KeyStore and evict from the cache. This is the crypto-shredding point.
- Eviction is local to the process. When several transhim instances share a KeyStore, the other instances keep the unwrapped intermediate key until its TTL expires, so crypto-shredding completes only after at most that TTL (plus the decrypt cache TTL, §9). Documentation must state this.
- There is no lazy creation in v1: `Encrypt` on a missing key returns `ErrKeyNotFound`. RGW always calls `keys/` before the first `datakey` (verified), so an `AutoCreate` option is not needed and is left out.

Shipped KeyStores: `memstore` (tests and dev only). Production stores (Postgres, etcd, a cloud database) are the user's responsibility. Document the interface contract clearly.

---

## 9. Decrypt Cache

- It is optional and off by default.
- Motivation: RGW calls `decrypt` on every read of an encrypted object, including HeadObject and every part of a multipart upload, always with the same wrapped key and context for that object (compat.md).
- Key: `sha256(lp(mount_id) || lp(key_name) || lp(context) || envelope_bytes)`, where `lp(x) = uvarint(len(x)) || x`. Length prefixes are used instead of separators because `context` is arbitrary bytes. Raw ciphertext is not used as the map key.
- Value: plaintext data key, held in a `[]byte` that is zeroed on eviction (best effort).
- Bounded by `MaxEntries` (LRU) and `TTL`. Both are required when the cache is enabled.
- Invalidation: on `DELETE keys/{name}`, all entries for `(mount_id, name)` are removed. This requires a secondary index from `(mount_id, name)` to a set of cache keys. Invalidation is local to the process: with several transhim instances, the others keep serving cached plaintext until TTL.
- Errors are never cached.
- Concurrent decrypts of the same request (same cache key) that miss the cache are merged into one backend call (`singleflight`); the others wait for its result. RGW sends such bursts (the parts of a multipart upload), and a KMS can take seconds per call and serve concurrent calls one after the other. The merged call does not inherit the cancellation of the request that started it, so that the waiting requests are not failed by another client going away. Without the cache nothing is merged.
- A cache hit never bypasses the authorizer: authorization runs before the lookup.
- A decrypt that is in flight while its key is deleted must not store its result afterwards. The cache counts invalidations, and a result is only stored if no invalidation happened since the backend call started.
- `datakey` and `encrypt` responses are never cached. However, the plaintext produced by `datakey` *may* be inserted into the decrypt cache, behind the option `WarmOnDatakey`, which defaults to false.
- Documentation must state that TTL equals the maximum delay for revocations performed directly in the cloud KMS, and for key deletions handled by another instance, to take effect.

## 10. Audit, Logging, Observability

- `AuditEvent{Time, Op, MountID, KeyName, CacheHit, Duration, Status, Err, RemoteAddr, RequestID}` is passed to the hook synchronously after each request, once the answer is written. Every request produces an event, including rejected ones and those that match no mount (their `Op`, `MountID`, or `KeyName` are empty). `Err` carries backend error details that the client does not get. The hook must not block; this is documented. No async helper is provided in v1.
- Logging uses `log/slog`. **Never log** plaintext, ciphertext, tokens, or request bodies. Key names may be logged.
- Metrics: no built-in exporter in v1. The audit hook is sufficient to build them.

## 11. Examples

- `examples/awskms`: an AWS KMS backend implementing `Backend` + `DataKeyGenerator`. AAD maps to `EncryptionContext{"transhim-aad": hex(sha256(AAD))}`. The hash keeps the value at a fixed length regardless of the context size, so it cannot exceed the KMS encryption context limit. This mapping is part of the on-disk compatibility contract of the example backend. `KeyRef` is the key ARN returned by KMS. The example `main` mounts:
  - `/v1/transit-kms` (mount ID `rgw-kms`) → AWS backend, with key name resolved as `alias/rgw/{name}`
  - `/v1/transit-sse-s3` (mount ID `rgw-sse-s3`) → hierarchical backend (root = AWS backend with a fixed `rootKeyName`, store = memstore with a "DO NOT USE IN PROD" warning)
- The README must include the matching Ceph RGW configuration snippet.

## 12. Compatibility Verification Tasks (must be done during implementation)

The design relies on assumptions taken from documentation and memory. The implementer must confirm each one and record the result in `docs/compat.md`. Items 3 and 5 concern non-RGW clients and are **deferred (D9)**; v1 requires items 1, 2, 4 (for RGW only), and 6.

Status: items 1, 2, 4, and 6 are **done** (M0) for Ceph 18.2.8, 19.2.7, and 20.2.5 against OpenBao 2.7.2. The results are in [compat.md](compat.md), the raw captures in `testdata/capture/`, and they are reproducible with `compat/capture.sh`. How RGW reacts to 403, 5xx, and a slow or unreachable Transit endpoint was added in M4.

1. Capture the actual HTTP requests made by Ceph RGW (Reef and Squid, and the latest available release) for SSE-KMS and SSE-S3 with `secret_engine = transit`. Do this with a recording proxy in front of a real Vault or OpenBao. Confirm the exact paths, methods, body fields (`context`?), the expected status codes, and whether `keys/` is called before the first `datakey`.
2. Confirm which `rgw_crypt_vault_secret_engine` compat value disables the legacy export path.
3. Confirm the behavior of the go-kms-wrapping transit wrapper with `renewable: false` from `lookup-self`.
4. Confirm whether any client parses the `vault:vN:` version, or validates the ciphertext format beyond treating it as opaque.
5. Capture the RustFS `vault-transit` request set before claiming UC5.
6. Confirm Vault's exact error status and message for "key not found" on decrypt and datakey.

Generate golden fixtures (request and response pairs) from a real Vault or OpenBao, and use them in `transhimtest` for API-shape conformance tests.

## 13. Testing Strategy

- Unit tests for the envelope codec (round-trip, fuzzing with `testing.F`), AAD construction, key name validation, prefix normalization, and error mapping.
- `transhimtest.FakeBackend`: AES-GCM with keys held in memory. It supports all optional interfaces and can inject errors and latency.
- `transhimtest.RunConformance(t, transhimtest.Conformance{Handler, Prefix, Token, ...})`: drives every v1 endpoint (including `encrypt`) and every negative case. The negative cases are: wrong key name, wrong context, tampered ciphertext, missing auth, oversized plaintext, an `exportable` key create, and cache invalidation after delete.
- Concurrency tests run with `-race` (cache, hierarchical backend).
- Golden fixtures (`transhimtest`, `TestFixtures`): the M0 captures are replayed against transhim, exchange by exchange. RGW's requests must get the recorded status and an answer of the recorded shape. For the direct probes of OpenBao, every deliberate difference is listed in the test with its reason; an unlisted difference fails.
- RGW integration test (`integration/`, skipped unless `TRANSHIM_TEST_RGW_ENDPOINT` is set; it is the v1 acceptance test, see M4): Ceph RGW from `compose.yml`, as in fujiwara/s3rp, pointed at a transhim server that the test starts (FakeBackend for SSE-KMS, the hierarchical backend for SSE-S3). It PUTs and GETs objects with SSE-KMS and SSE-S3, with and without the decrypt cache, and verifies that bucket deletion deletes the bucket's key. It also injects failures of the Transit endpoint and checks that RGW fails closed. It is a Go module of its own, so that the AWS SDK it uses is not a dependency of transhim. CI runs it against the three Ceph releases.

## 14. Security Considerations

- TLS is the user's responsibility (they build the `http.Server`). The docs must strongly recommend TLS or mTLS, because data keys cross the wire in plaintext. That is inherent to the Transit datakey API.
- Plaintext buffers are zeroed after use where practical. Go's garbage collector and copies prevent any guarantee, and the docs must say so.
- Constant-time comparison is used for any token checks in examples (`crypto/subtle`).
- No key material appears in errors, logs, or audit events.
- Authorization per key name belongs in the authorizer, because RGW does not check whether an S3 user may use a given KMS key ID. The docs must highlight this.
- The `mount_id` and AAD format are part of the on-disk compatibility contract. Changing either one breaks all existing ciphertexts. This is why `mount_id` is required and never derived from the prefix: the prefix can then change freely.

## 15. Milestones

0. **M0 – Capture** (done): record the real requests of Ceph RGW (SSE-KMS and SSE-S3) against Vault or OpenBao, covering §12 items 1, 2, 4, and 6. These results determine the exact v1 endpoint set (see the v1 scope rule in §2), the API shape, the "key not found" response, and whether lazy key creation is needed, so they come before M1. Record them in `docs/compat.md`.
1. **M1 – Core** (done): server, routing, envelope, AAD, error mapping, `datakey/plaintext`, `decrypt`, `encrypt`, authorizer, FakeBackend, unit tests.
2. **M2 – Key ops** (done): `keys` create/config/delete, `KeyLifecycle`, decrypt cache with invalidation, audit hook.
3. **M3 – Hierarchical backend** (done) + memstore + tests.
4. **M4 – RGW acceptance** (done): golden fixtures from the M0 capture, conformance suite, and the RGW integration test (§13) passing for SSE-KMS and SSE-S3. This is the v1 acceptance criterion.
5. **M5 – Examples & docs**: AWS KMS example, RGW configuration guide, README.

Not in v1 (see §3): token stubs, `sys/health`, `GET keys/{name}`, and §12 items 3 and 5.

The pre-development stub `cmd/transhim` was removed in M1 (NG6); releases carry no binaries.

Definition of done for each milestone: tests pass with `-race`, `go vet` and `staticcheck` are clean, and exported identifiers are documented.

## 16. Open Questions

- Q1. Should transhim offer a key-name → backend routing hook within a single mount? This would let one prefix serve multiple KMS backends based on the key name. It is currently out of scope; users can implement it inside their Backend.
- Q2. Should a minimal `cmd/transhim` with a YAML config be provided in v2 for users who do not want to write Go?
