# Changelog

## [v0.3.1](https://github.com/fujiwara/transhim/compare/v0.3.0...v0.3.1) - 2026-11-19

- Require transhim v0.3.0 in the examples by @fujiwara in https://github.com/fujiwara/transhim/pull/25

## [v0.3.0](https://github.com/fujiwara/transhim/compare/v0.2.0...v0.3.0) - 2026-11-19

- Require transhim v0.2.0 in the examples by @fujiwara in https://github.com/fujiwara/transhim/pull/15
- Add hierarchical.ReadOnly for servers that must not write to the KeyStore by @fujiwara in https://github.com/fujiwara/transhim/pull/17
- Run the tests for pull requests and for main only by @fujiwara in https://github.com/fujiwara/transhim/pull/19
- Test sops as a second Transit client by @fujiwara in https://github.com/fujiwara/transhim/pull/18
- Record what RustFS needs from a Transit endpoint by @fujiwara in https://github.com/fujiwara/transhim/pull/20
- Refuse associated_data instead of ignoring it by @fujiwara in https://github.com/fujiwara/transhim/pull/21
- Test OpenBao's transit seal as a Transit client by @fujiwara in https://github.com/fujiwara/transhim/pull/22
- Serve key reads and the token lookup for a Kubernetes KMS plugin by @fujiwara in https://github.com/fujiwara/transhim/pull/23
- Record that RustFS works behind a wrapper, and what the wrapper adds by @fujiwara in https://github.com/fujiwara/transhim/pull/24

## [v0.2.0](https://github.com/fujiwara/transhim/compare/v0.1.0...v0.2.0) - 2026-11-18

- Require transhim v0.1.0 in the example modules by @fujiwara in https://github.com/fujiwara/transhim/pull/6
- Add a KeyStore conformance suite and an SQL key store example by @fujiwara in https://github.com/fujiwara/transhim/pull/8
- Pass the request context to authorizers and audit hooks by @fujiwara in https://github.com/fujiwara/transhim/pull/11
- Add a guide to writing a production server by @fujiwara in https://github.com/fujiwara/transhim/pull/10
- Support Ceph 21 (umbrella), drop Ceph 18 (reef) by @fujiwara in https://github.com/fujiwara/transhim/pull/14
- Document the HTTP API by @fujiwara in https://github.com/fujiwara/transhim/pull/13
- Log the request context in the example servers by @fujiwara in https://github.com/fujiwara/transhim/pull/12
- Bump postgres from 18.1 to 18.6 by @dependabot[bot] in https://github.com/fujiwara/transhim/pull/9

## [v0.1.0](https://github.com/fujiwara/transhim/commits/v0.1.0) - 2026-11-17

The first release. transhim is a Go framework for building servers that speak the HashiCorp Vault Transit HTTP API while delegating the cryptography to a backend you provide, typically a cloud KMS. Its first target is Ceph RGW server-side encryption (SSE-KMS and SSE-S3).

- Serves the part of the Transit API that Ceph RGW uses (`datakey/plaintext`, `decrypt`, key create/config/delete), plus `encrypt`.
- `Backend`: the interface to implement against a KMS (`Encrypt`, `Decrypt`), with the optional `DataKeyGenerator` and `KeyLifecycle`.
- Every ciphertext is bound to its mount ID, key name, and context.
- `hierarchical`: per-bucket keys for SSE-S3 without one KMS key per bucket. One root key stays in the KMS; the bucket keys are kept, wrapped, in a `KeyStore` you provide. Deleting a bucket's key shreds its data.
- Decrypt cache, with concurrent requests for the same key sharing one KMS call, for slow KMS services.
- Authorization hook (`Authorizer`, `StaticTokenAuthorizer`) and audit hook.
- `transhimtest`: an in-memory backend, and `RunConformance` to check a server built on your own backend.
- Examples: backends and servers for AWS KMS (`examples/awskms`) and SAKURA Cloud KMS (`examples/sakurakms`).
- Tested against real Ceph RGW 18.2.8 (reef), 19.2.7 (squid), and 20.2.5 (tentacle). `docs/rgw.md` is the configuration guide; `docs/compat.md` records what RGW sends and how it reacts to failures.

Changes by pull request:

- Bump Songmu/tagpr from 1.21.0 to 1.22.0 by @dependabot[bot] in https://github.com/fujiwara/transhim/pull/2
- Bump github.com/ogen-go/ogen from 1.24.0 to 1.25.0 in /examples/sakurakms by @dependabot[bot] in https://github.com/fujiwara/transhim/pull/5
