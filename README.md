# transhim

A Go framework for building HashiCorp Vault Transit–compatible API servers whose actual cryptography is delegated to user-supplied backends (typically a cloud KMS). The name means "**tran**sit **shim**".

The first target is Ceph RGW server-side encryption (SSE-KMS and SSE-S3).

**Status: pre-release, under development.** The core is implemented (`datakey/plaintext`, `decrypt`, `encrypt`, authorization). Still missing for Ceph RGW SSE-S3: key create/config/delete, the decrypt cache, and the hierarchical backend. The API may change until the first release.

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
- `transhimtest.FakeBackend` is an in-memory backend for tests.

## Development

The development environment follows [fujiwara/s3rp](https://github.com/fujiwara/s3rp): `compose.yml` runs Ceph RGW from the plain release image, bootstrapped by `docker/ceph-demo.sh`, plus OpenBao as the reference Transit implementation.

```console
$ make test       # unit tests
$ make capture    # re-capture RGW's Transit requests into testdata/capture/
```

`make capture` needs docker compose, curl, jq, and the aws CLI. See [compat/capture.sh](compat/capture.sh) for its options (`CEPH_IMAGE`, `EMPTY_KEY_WRITES`, `CEPH_EXTRA_ARGS`).

Access RGW via `http://127.0.0.1:7480`, never `localhost`: RGW resolves other host names as virtual-hosted bucket names.

## LICENSE

MIT

## Author

fujiwara
