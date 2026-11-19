# transhim

A Go framework for building HashiCorp Vault Transit–compatible API servers whose actual cryptography is delegated to user-supplied backends (typically a cloud KMS). The name means "**tran**sit **shim**".

The first target is Ceph RGW server-side encryption (SSE-KMS and SSE-S3).

**Status: v0.x.** It is feature complete for Ceph RGW and tested against real RGW releases 19.2.7 (squid), 20.2.5 (tentacle), and 21.2.0 (umbrella). Until v1.0 the Go API may change between minor versions. What is bound into ciphertexts (the mount ID, the AAD and envelope formats) is not going to change.

What it does:

- Serves the part of the Transit API that Ceph RGW uses (`datakey/plaintext`, `decrypt`, key create/config/delete) plus `encrypt`.
- Delegates the cryptography to a small Go interface you implement against your KMS: `Encrypt` and `Decrypt`.
- Binds every ciphertext to its mount, key name, and context, so that it cannot be decrypted under another one.
- Offers per-bucket keys without one KMS key per bucket (the hierarchical backend), a decrypt cache for slow KMS services, an authorization hook, and an audit hook.

What it is not: a Vault replacement, or a ready-made server. You write your own `main`; there are examples for [AWS KMS](examples/awskms) and [SAKURA Cloud KMS](examples/sakurakms).

Documents:

- [docs/server.md](docs/server.md): writing a server for production: the backend, authorization, per-bucket keys, caches, and operation
- [docs/api.md](docs/api.md): the HTTP API: which Transit endpoints are served, how each is processed, and the differences from Vault
- [docs/rgw.md](docs/rgw.md): configuring Ceph RGW, and what to know before going live
- [docs/compat.md](docs/compat.md): what Ceph RGW really sends to a Transit endpoint, how it reacts to failures, and where transhim differs from Vault; also what was seen with sops, OpenBao's transit seal, a Kubernetes KMS plugin, and RustFS
- [examples/awskms](examples/awskms): an AWS KMS backend and an example server
- [examples/sakurakms](examples/sakurakms): the same for SAKURA Cloud KMS, a KMS without a parameter for authenticated data
- [examples/sqlkeystore](examples/sqlkeystore): a durable `KeyStore` for the per-bucket keys, on PostgreSQL or SQLite

## Usage

```console
$ go get github.com/fujiwara/transhim
```

transhim is a library. You implement `transhim.Backend` against your KMS and write your own `main`:

```go
// Backend wraps and unwraps small blobs with a named key.
// It must cryptographically bind req.AAD (for example as AES-GCM AAD,
// or as the encryption context of a cloud KMS).
type myKMS struct{ /* ... */ }

func (k *myKMS) Encrypt(ctx context.Context, req transhim.EncryptRequest) (transhim.WrappedKey, error)
func (k *myKMS) Decrypt(ctx context.Context, req transhim.DecryptRequest) ([]byte, error)

func main() {
	// For per-bucket keys (SSE-S3): one root key in the KMS, and a random
	// key per bucket, kept wrapped in a KeyStore you provide.
	sseS3, err := hierarchical.New(&myKMS{}, "transhim-root", store)
	if err != nil {
		log.Fatal(err)
	}
	srv, err := transhim.NewServer(
		// prefix (routing only), mount ID (bound into every ciphertext), backend
		transhim.Mount("/v1/transit-kms", "rgw-kms", &myKMS{}),
		transhim.Mount("/v1/transit-sse-s3", "rgw-sse-s3", sseS3),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(os.Getenv("VAULT_TOKEN"))),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServeTLS(":8200", "cert.pem", "key.pem", srv))
}
```

The matching Ceph RGW configuration is in [docs/rgw.md](docs/rgw.md).

The least to know:

- **The mount ID is permanent.** It is part of the data bound to every ciphertext. Changing it makes all existing ciphertexts of that mount undecryptable. The prefix, in contrast, can change freely.
- **The `KeyStore` is state you must not lose.** A lost entry makes every object of that bucket unreadable. `keystore/memstore` is for tests and development only.
- **Use TLS.** The Transit datakey API returns data keys in plaintext.
- **Authorization per key is yours to do.** Ceph RGW does not check whether an S3 user may use a given key ID.
- **Set time limits on KMS calls.** Neither transhim nor Ceph RGW does.

[docs/server.md](docs/server.md) has the rest: how to write and test a backend, authorizers, the decrypt cache for slow KMS services, the audit hook, and what running it takes.

## Development

The development environment follows [fujiwara/s3rp](https://github.com/fujiwara/s3rp): `compose.yml` runs Ceph RGW from the plain release image, bootstrapped by `docker/ceph-demo.sh`, plus OpenBao as the reference Transit implementation.

```console
$ make test          # unit tests
$ make integration   # acceptance test: starts Ceph RGW and runs SSE-KMS and SSE-S3 against transhim
$ make capture       # re-capture RGW's Transit requests into testdata/capture/
```

`make integration` needs docker compose. The test (in `integration/`, a Go module of its own because it uses the AWS SDK) starts a transhim server at `127.0.0.1:8201`, where the RGW of `compose.yml` expects its Transit endpoint. Another Ceph release: `CEPH_IMAGE=quay.io/ceph/ceph:v19.2.7 make integration`.

The AWS KMS example is tested against the [AWS Emulator](https://github.com/aws/aws-emulator), the SAKURA Cloud KMS example against [sakumock](https://github.com/sacloud/sakumock); see their READMEs.

`make capture` needs docker compose, curl, jq, and the aws CLI. See [compat/capture.sh](compat/capture.sh) for its options (`CEPH_IMAGE`, `EMPTY_KEY_WRITES`, `CEPH_EXTRA_ARGS`).

Access RGW via `http://127.0.0.1:7480`, never `localhost`: RGW resolves other host names as virtual-hosted bucket names.

## LICENSE

MIT

## Author

fujiwara
