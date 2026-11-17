# transhim

A Go framework for building HashiCorp Vault Transit–compatible API servers whose actual cryptography is delegated to user-supplied backends (typically a cloud KMS). The name means "**tran**sit **shim**".

The first target is Ceph RGW server-side encryption (SSE-KMS and SSE-S3).

**Status: pre-release, under development.** The server is implemented: `datakey/plaintext`, `decrypt`, `encrypt`, key create/config/delete, authorization, the decrypt cache, and the audit hook. The hierarchical backend (per-bucket keys for Ceph RGW SSE-S3 without one KMS key per bucket) is implemented as well. It is tested against real Ceph RGW releases 18.2.8 (reef), 19.2.7 (squid), and 20.2.5 (tentacle), for SSE-KMS and SSE-S3. Still missing: the AWS KMS example. The API may change until the first release.

- [docs/DESIGN.md](docs/DESIGN.md): design document
- [docs/compat.md](docs/compat.md): what Ceph RGW really sends to a Transit endpoint, and how the reference implementation answers

## Usage

transhim is a library. You implement `transhim.Backend` against your KMS and write your own `main`:

```go
// Backend wraps and unwraps small blobs with a named key.
// It must cryptographically bind req.AAD (for example as AES-GCM AAD,
// or as the encryption context of a cloud KMS).
type myKMS struct{ /* ... */ }

func (k *myKMS) Encrypt(ctx context.Context, req transhim.EncryptRequest) (transhim.WrappedKey, error)
func (k *myKMS) Decrypt(ctx context.Context, req transhim.DecryptRequest) ([]byte, error)

func main() {
	srv, err := transhim.NewServer(
		// prefix (routing only), mount ID (bound into every ciphertext), backend
		transhim.Mount("/v1/transit", "rgw-kms", &myKMS{}),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(os.Getenv("VAULT_TOKEN"))),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServeTLS(":8200", "cert.pem", "key.pem", srv))
}
```

Things to know:

- **The mount ID is permanent.** It is part of the data bound to every ciphertext. Changing it makes all existing ciphertexts of that mount undecryptable. The prefix, in contrast, can change freely.
- **Use TLS.** The Transit datakey API returns data keys in plaintext.
- **Authorization per key is yours to do.** Ceph RGW does not check whether an S3 user may use a given key ID. Check it in the `Authorizer` or in the backend.
- An `Authorizer` is required. `transhim.AllowUnauthenticated()` turns that off explicitly.
- Backends report failures by wrapping `ErrKeyNotFound`, `ErrCiphertextMismatch`, `ErrPermissionDenied`, or `ErrUpstream`. Details go to the log, never to the client.
- A backend may also implement `DataKeyGenerator` if its KMS has a native "generate data key" call.
- A backend may implement `KeyLifecycle` to create and delete keys when the client asks (Ceph RGW does, for SSE-S3: one key per bucket). Without it, those requests succeed and do nothing, and keys are expected to exist in the KMS.
- `transhimtest.FakeBackend` is an in-memory backend for tests.
- `transhimtest.RunConformance` checks a server built on your backend: it drives every endpoint the way Ceph RGW does, including the requests that must be rejected.

### Per-bucket keys: the hierarchical backend

For SSE-S3, Ceph RGW creates one key per bucket and deletes it with the bucket. Creating a KMS key per bucket is usually too slow and too expensive. `hierarchical.Backend` keeps one root key in the KMS and gives every key name a random intermediate key, stored wrapped by the root key in a `KeyStore` you provide:

```go
sseS3, err := hierarchical.New(
	&myKMS{},          // root backend
	"transhim-root",   // the only key name the root backend ever sees
	store,             // your hierarchical.KeyStore
)
// ...
transhim.Mount("/v1/transit-sse-s3", "rgw-sse-s3", sseS3)
```

- **The `KeyStore` is state you must not lose.** A lost entry makes every object encrypted with that key unreadable. The stored keys are wrapped, so the store need not be secret, but it must be durable. `keystore/memstore` is for tests and development only.
- **The root key name is permanent**, like the mount ID: both are bound into the stored keys.
- Deleting a key deletes its intermediate key, which makes the bucket's data unreadable (crypto-shredding). This is best effort: RGW does not always delete the key of a deleted bucket (see [docs/compat.md](docs/compat.md)), so orphaned keys can stay in the store.
- Unwrapped intermediate keys are cached in memory (`hierarchical.WithKeyCacheTTL`, default 5 minutes). Loading one costs a `KeyStore` read and a KMS call; requests for the same key that arrive meanwhile wait for that load instead of starting their own. With several transhim instances sharing a store, a key deleted through one instance stays usable through the others until that TTL has passed.

### Decrypt cache

Ceph RGW calls `decrypt` on every read of an encrypted object, including HeadObject and each part of a multipart upload, always with the same wrapped key. The decrypt cache answers those without calling the KMS:

```go
transhim.WithDecryptCache(transhim.DecryptCacheConfig{
	MaxEntries: 10000,
	TTL:        5 * time.Minute,
})
```

Identical decrypts that arrive at the same time share one KMS call, which matters when the KMS is slow.

It is off by default. It holds plaintext data keys in memory, so **the TTL is the longest time a revocation can take to become effective** when it happens behind the server's back: disabling a key directly in the KMS, or deleting a key through another transhim instance. Deleting a key through the same instance removes its entries at once. Requests are authorized before the cache is consulted.

### Audit

`transhim.WithAuditHook(fn)` calls `fn` with an `AuditEvent` (operation, mount ID, key name, status, error, cache hit, duration, peer address, request ID) after every request. The hook runs synchronously and must not block. Events never contain key material, ciphertexts, or tokens.

## Development

The development environment follows [fujiwara/s3rp](https://github.com/fujiwara/s3rp): `compose.yml` runs Ceph RGW from the plain release image, bootstrapped by `docker/ceph-demo.sh`, plus OpenBao as the reference Transit implementation.

```console
$ make test          # unit tests
$ make integration   # acceptance test: starts Ceph RGW and runs SSE-KMS and SSE-S3 against transhim
$ make capture       # re-capture RGW's Transit requests into testdata/capture/
```

`make integration` needs docker compose. The test (in `integration/`, a Go module of its own because it uses the AWS SDK) starts a transhim server at `127.0.0.1:8201`, where the RGW of `compose.yml` expects its Transit endpoint. Another Ceph release: `CEPH_IMAGE=quay.io/ceph/ceph:v19.2.7 make integration`.

`make capture` needs docker compose, curl, jq, and the aws CLI. See [compat/capture.sh](compat/capture.sh) for its options (`CEPH_IMAGE`, `EMPTY_KEY_WRITES`, `CEPH_EXTRA_ARGS`).

Access RGW via `http://127.0.0.1:7480`, never `localhost`: RGW resolves other host names as virtual-hosted bucket names.

## LICENSE

MIT

## Author

fujiwara
