# AGENTS.md

transhim is a Go library for building Vault Transit compatible servers that delegate cryptography to a user-supplied backend. The first client is Ceph RGW.

## Documents

- [docs/DESIGN.md](docs/DESIGN.md): the design document: goals and non-goals, the HTTP API, the envelope and AAD formats, the Go interfaces, what was deferred (D1...), and the reasons. Read it before changing behavior. It is for contributors; user documentation does not link to it.
- [docs/compat.md](docs/compat.md): what Ceph RGW (and sops, RustFS) was observed to send and how it reacts. The source of truth for client behavior.
- [docs/server.md](docs/server.md), [docs/api.md](docs/api.md), [docs/rgw.md](docs/rgw.md), [README.md](README.md): user documentation. Keep them in step with the code.

## Layout

- The root package is the server. It depends on the standard library and `golang.org/x` only.
- `hierarchical/`, `keystore/memstore/`: per-key intermediate keys under one root key.
- `transhimtest/`: `FakeBackend` and the conformance suites for backends and key stores.
- `integration/` and `examples/*` are Go modules of their own, so that their dependencies (AWS SDK, SAKURA Cloud SDK, database drivers) stay out of the library. Run their checks inside those directories.

## Checks

```console
$ go fmt ./... && go fix ./... && go vet ./... && staticcheck ./...
$ make test          # unit tests, with -race
$ make integration   # acceptance test against Ceph RGW; needs docker compose
```

## Rules

- What is bound into ciphertexts must not change: the envelope format, the AAD format, and the formats of the hierarchical backend and the examples. Existing ciphertexts must stay decryptable.
- Never log or put into errors and audit events: plaintexts, ciphertexts, tokens, request bodies.
- Key create, config, and delete answer with an empty `204`. Ceph RGW before 20 depends on it.
- Exported identifiers are documented. Behavior changes come with tests and with updates to the user documentation.
