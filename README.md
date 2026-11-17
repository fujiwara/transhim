# transhim

A Go framework for building HashiCorp Vault Transit–compatible API servers whose actual cryptography is delegated to user-supplied backends (typically a cloud KMS). The name means "**tran**sit **shim**".

The first target is Ceph RGW server-side encryption (SSE-KMS and SSE-S3).

**Status: pre-release.** The design is settled and the client behavior has been captured; the library itself is not implemented yet.

- [docs/DESIGN.md](docs/DESIGN.md): design document
- [docs/compat.md](docs/compat.md): what Ceph RGW really sends to a Transit endpoint, and how the reference implementation answers

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
