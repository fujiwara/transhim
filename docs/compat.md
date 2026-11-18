# Compatibility notes

Results of the verification tasks in [DESIGN.md](DESIGN.md) §12. Everything here was observed on the wire or read in the client's source; nothing is taken from documentation alone.

## How this was captured

```
aws CLI --> Ceph RGW --> vaultrec (records) --> OpenBao (reference Transit)
```

- `compat/capture.sh` starts OpenBao and Ceph RGW from `compose.yml`, puts the recording proxy `tools/vaultrec` between them, runs a fixed list of S3 operations, and then sends a set of direct probes to OpenBao through the same proxy.
- RGW uses two Transit mounts: `/v1/transit-kms` for SSE-KMS and `/v1/transit-sse-s3` for SSE-S3. Direct probes use `/v1/transit`.
- The captures are in `testdata/capture/`, one JSON line per exchange. Marker lines say which S3 operation or probe caused the exchanges that follow, and how the S3 client saw it end.

```console
$ compat/capture.sh                                         # Ceph image pinned in compose.yml
$ CEPH_IMAGE=quay.io/ceph/ceph:v19.2.7 compat/capture.sh
$ EMPTY_KEY_WRITES=1 compat/capture.sh                      # see "Key writes must answer with an empty body"
$ jq -r -f compat/summary.jq testdata/capture/ceph-v20.2.5.jsonl
```

| component | versions |
|---|---|
| Ceph RGW | 19.2.7 (squid), 20.2.5 (tentacle), 21.2.0 (umbrella) |
| reference Transit | OpenBao 2.7.2, dev mode |
| S3 client | aws-cli 2.36.44 |

The capture files contain plaintext data keys. They belong to a throwaway dev server that no longer exists. The Vault token is redacted by the recorder.

Source references are to `src/rgw/rgw_kms.cc` and `src/rgw/rgw_crypt.cc` in the Ceph repository at the release tags above.

## §12 item 1: what RGW sends

RGW calls exactly these five endpoints, on all three releases. It never calls `encrypt`, `GET keys/{name}`, `auth/token/*`, or `sys/*`.

| request | body | sent when |
|---|---|---|
| `POST {prefix}/datakey/plaintext/{name}` | `{"context":"<base64>"}` | an encrypted object is written: PutObject, CreateMultipartUpload, CopyObject destination |
| `POST {prefix}/decrypt/{name}` | `{"context":"<base64>","ciphertext":"vault:v1:..."}` | an encrypted object is read: GetObject (also ranged), HeadObject, each UploadPart, CopyObject source; on tentacle and umbrella also CompleteMultipartUpload |
| `POST {prefix}/keys/{name}` | `{"type":"chacha20-poly1305","derived":true}` | SSE-S3 only: the first encrypted write to a bucket |
| `POST {prefix}/keys/{name}/config` | `{"deletion_allowed":true}` | SSE-S3 only: DeleteBucket of a bucket that has a key |
| `DELETE {prefix}/keys/{name}` | none | SSE-S3 only: right after `config` |

Details that matter to an implementation:

- **Headers.** RGW sends `Accept: */*`, `Content-Length`, and `X-Vault-Token`. Squid and tentacle send **no `Content-Type`**, and send `X-Vault-Token` **twice** with the same value (a duplicated `append_header` call). Umbrella sends `Content-Type: application/json` and the token once. A server must take the first value and must not require a content type.
- **Methods.** Only `POST` and `DELETE`. `PUT` is never used.
- **`context`** is always present. It is the base64 of a JSON object: `{"aws:s3:arn":"arn:aws:s3::<owner>:<bucket>/<object>"}`, plus the client's `x-amz-server-side-encryption-context` entries if any. RGW stores it with the object and sends the identical value on every decrypt. CopyObject decrypts with the source object's context and requests a new data key with the destination's.
- **The context can be forged with SSE-KMS.** An entry `aws:s3:arn` in the client's `x-amz-server-side-encryption-context` replaces RGW's: the S3 user can name any object there, on all three releases (squid, tentacle, umbrella). With SSE-S3 the client has no say: RGW rejects a PutObject that carries an encryption context (`400 InvalidArgument`) without calling the Transit endpoint. So the context tells a server which object an SSE-S3 request is for; for SSE-KMS it only says what the S3 user claims (`integration/`, `TestRGWContext`).
- **`bits`** is never sent; RGW relies on the 256-bit default.
- **Response fields read.** `data.plaintext` and `data.ciphertext` from `datakey`, `data.plaintext` from `decrypt`. Nothing else is read (`key_version`, `request_id`, and the other envelope fields are ignored). Responses to `keys/...` calls are expected to be empty; see below.
- **Key names.** For SSE-KMS it is the client's key ID, verbatim. RGW itself rejects a key ID containing `/` (400 `InvalidArgument`) without calling Vault, and rejects `aws:kms` without a key ID. For SSE-S3 it is `rgw_crypt_sse_s3_key_template` expanded; the default `%bucket_id` gives the bucket marker, e.g. `1434f035-2747-4d60-a14f-5a0efa651729.4126.2`. The template may also use `%owner_id`.
- **Errors.** A `datakey` or `decrypt` call answered with `400` reaches the S3 client as `400 InvalidArgument`, "Failed to retrieve the actual key, kms-keyid: ...". A missing key and a ciphertext that does not verify look the same to the client. Other statuses are passed on differently; see "How RGW reacts to a failing Transit endpoint".

### Is `keys/` called before the first `datakey`?

Yes, always. On the first SSE-S3 write to a bucket, RGW calls `POST keys/{name}`, and only then `datakey/plaintext/{name}`. It then stores the key name in a bucket attribute and does not call `keys/` again for that bucket. This holds whether SSE-S3 comes from a request header or from the bucket's default encryption. Setting the bucket default alone (PutBucketEncryption) calls nothing.

So lazy key creation inside `datakey` is not needed for RGW.

### Key writes must answer with an empty body

OpenBao (and Vault) answer `POST keys/{name}` and `POST keys/{name}/config` with `200` and the key's metadata. RGW expects an empty response:

| RGW | `POST keys/{name}` has a body | `POST keys/{name}/config` has a body |
|---|---|---|
| 19.2.7 | logs an error, continues | **treats it as a failure and never sends `DELETE`** |
| 20.2.5 | logs an error, continues | continues |
| 21.2.0 | continues | continues |

With a current OpenBao, squid therefore never deletes a bucket key: it stays behind with `deletion_allowed` set. This is visible in `ceph-v19.2.7.jsonl` (three `config` calls, no `DELETE`). Everything else works; only the key is left behind.

This is a bug in RGW, [Ceph issue 65626](https://tracker.ceph.com/issues/65626): RGW looks at the length of the answer's body, not at the status. It was fixed for tentacle ([ceph/ceph#57046](https://github.com/ceph/ceph/pull/57046)); the backport to squid ([ceph/ceph#73115](https://github.com/ceph/ceph/pull/73115)) was merged after 19.2.7. Reef (18.2.x, end of life) has the same bug and no fix.

The `*-empty-key-writes.jsonl` captures repeat the run with the recorder turning those two responses into `204` with no body. Then all three releases send `DELETE` after `config`. **transhim must answer key create and key config with `204` and an empty body.** This is a place where transhim works better with RGW than the reference does.

### When bucket keys are deleted, and when they leak

- DeleteBucket on a bucket with a key: `config`, then `DELETE`. RGW ignores the outcome of both; the bucket is removed either way.
- DeleteBucket on a non-empty bucket fails (`409 BucketNotEmpty`) before any key call.
- DeleteBucket on a bucket that never had an SSE-S3 object: no key calls.
- **DeleteBucketEncryption forgets the key without deleting it.** It only clears the bucket attribute. Consequences:
  - A later SSE-S3 write to the same bucket calls `POST keys/{name}` again with the **same name**. Objects written before must stay readable, so key creation must be idempotent and must keep the existing key.
  - If the bucket is deleted while the attribute is cleared, no `DELETE` is ever sent and the key is orphaned.

Crypto-shredding by bucket deletion is therefore best effort. A backend that stores per-bucket keys needs its own way to find orphans.

## §12 item 2: the `compat` option

From the source (`TransitSecretEngine` constructor), identical on all three releases:

- `compat` is a parameter of the engine name: `rgw_crypt_vault_secret_engine = transit compat=N`. `0` = new API only, `1` = new API plus the legacy export path for old objects, `2` = legacy only.
- When it is not given, the default depends on the prefix: `2` if the prefix ends with `/export/encryption-key`, otherwise **`0`**.

So a plain `rgw_crypt_vault_secret_engine = transit` with a prefix such as `/v1/transit` already disables the legacy export path. No `compat` option is needed. The captures confirm it: no request to `/export/...` on any release.

Even with `compat=0`, RGW reads an object through the legacy path if its stored key ID contains `/`. RGW refuses to write such objects, so this only concerns data written by old releases in legacy mode.

## §12 item 4: is the ciphertext parsed?

No. RGW stores `data.ciphertext` in an object attribute and sends it back unchanged. The string `vault:` does not occur in `rgw_kms.cc`. The ciphertext is opaque to RGW, including its `vault:vN:` prefix.

## §12 item 6: "key not found"

`datakey/plaintext` and `decrypt` on a missing key both answer:

```
400 {"errors":["encryption key not found"]}
```

This matches the mapping in DESIGN.md §6.8.

## Reference behavior worth knowing (direct probes)

These are OpenBao's answers, recorded for the golden fixtures. Where transhim deliberately differs, it says so.

| probe | OpenBao | note |
|---|---|---|
| any success with data | `200`, `Content-Type: application/json`, `Cache-Control: no-store`; top-level `request_id`, `lease_id`, `renewable`, `lease_duration`, `data`, `wrap_info`, `warnings`, `auth` | |
| `datakey` with no body, `{}`, or `{"context":""}` | `200` | an absent and an empty context are the same |
| `datakey` `bits` 128 / 256 / 512 | `200` | any other value: `400 invalid bit length` |
| `datakey` / `decrypt` with a context on a non-derived key | context is **ignored**: a ciphertext made with a context decrypts without it, and the reverse | transhim binds the context whenever it is present. RGW always sends the same context, so this is compatible, and stricter. |
| `datakey` / `decrypt` on a derived key without context | `400 missing 'context' for key derivation; ...` | RGW's SSE-S3 keys are derived |
| `decrypt` on a derived key with the wrong context | `400 chacha20poly1305: message authentication failed` | |
| `decrypt` with the wrong key or a tampered ciphertext | `400 cipher: message authentication failed` | transhim answers `400 invalid ciphertext` |
| `decrypt` without the `vault:` prefix / bad base64 / unknown version | `400 invalid ciphertext: no prefix` / `...: could not decode base64` / `...: version is too new` | |
| missing `ciphertext` / `plaintext` | `400 missing ciphertext to decrypt` / `400 missing plaintext to encrypt` | |
| malformed JSON | `400 failed to decode JSON input: ...` | |
| `encrypt` on a missing key | `200`; the key is **created** | transhim does not auto-create (DESIGN.md §6.2) |
| `POST keys/{name}` (also with `PUT`) | `200` with key metadata; repeating it returns the existing key | transhim answers `204`, empty (see above) |
| `POST keys/{name}` with `exportable: true` | `200` | transhim rejects it |
| `POST keys/{name}/config` | `200` with key metadata; `400` if the key is missing | transhim answers `204`, empty |
| `DELETE keys/{name}` | `204`; `400` without `deletion_allowed`; `400` if the key is missing | transhim treats a missing key as success |
| `GET keys/{name}` on a missing key | `404 {"errors":[]}` | |
| `GET` on `datakey` | `405` | |
| unknown operation / unknown mount | `404` | |
| no token / wrong token | `403 {"errors":["permission denied"]}` | |

## Other observations

- **Decrypt volume.** RGW calls `decrypt` for every read of an encrypted object (but see umbrella's key cache below), including HeadObject and every part of a multipart upload. A 1000-part upload is 1000 decrypt calls for the same wrapped key. This is the case the decrypt cache (DESIGN.md §9) exists for.
- **Umbrella has a key cache of its own, for SSE-KMS.** From the source (`rgw_kms_cache.cc`) and the options of 21.2.0: `rgw_crypt_s3_kms_cache_enabled` is on by default and keeps up to 128 unwrapped data keys (`rgw_crypt_s3_kms_cache_max_size`) for 60 seconds (`rgw_crypt_s3_kms_cache_positive_ttl`) in the Linux kernel keyring. It caches failures as well: a missing key for 120 seconds, other errors for 10. SSE-S3 is not cached. Where it is in effect, a repeated read of an SSE-KMS object within the TTL does not reach the Transit endpoint: no `decrypt` call, no audit event, and a key disabled in the KMS stays usable for that long on top of transhim's own caches.
  - It was **not seen working** here. In a container with docker's default seccomp profile the keyring is not available and RGW turns the cache off at startup: that is the setup of the captures and of the acceptance test, where umbrella calls `decrypt` on every read like the releases before. With the keyring allowed (`seccomp=unconfined`), the first cache hit failed (`kms_error_secret_store`; the S3 request failed), after which RGW turned the cache off by itself. How it behaves on a real deployment is not verified.
- **CopyObject of an encrypted object** answers `501 NotImplemented` on squid, before any Vault call. It works on tentacle and umbrella. This is RGW's own limitation.
- **Token file.** RGW reads the token from a file that group and others must not be able to access (squid; tentacle and umbrella allow up to `0740`). `docker/ceph-demo.sh` writes it as the `ceph` user for that reason.
- **aws CLI.** aws-cli 2.36 crashes while printing an RGW error whose `<Message>` is empty (squid sends those). The capture script reads the status and error code from the wire instead.

## How RGW reacts to a failing Transit endpoint

Observed with the acceptance test (`integration/`, `TestRGWFaults` and `TestRGWEndpointDown`), which puts a fault in front of transhim for one kind of request at a time. The S3 operations are PutObject (fails in `datakey`) and GetObject (fails in `decrypt`) with SSE-KMS; both react the same way.

| Transit endpoint answers | S3 client sees |
|---|---|
| `400` (missing key, invalid ciphertext) | `400 InvalidArgument` |
| `403` | `403 AccessDenied` |
| `500` | `500 InternalError` |
| `502` | `500 InternalError` |
| `503` | `503 ServiceUnavailable` |
| `200` without `data`, or not JSON | `400 InvalidArgument` |
| connection reset, or nothing listening | `500 InternalError` |
| answer after 3 s, or after 75 s | success |

All three releases react the same way. The 75 second wait was measured on squid and tentacle only.

What follows from it:

- **RGW fails closed.** In none of these cases was an object stored unencrypted or handed out. A PutObject whose `datakey` failed leaves no object behind.
- **RGW does not retry**, and it sets no timeout that 75 seconds would reach: a slow key service makes S3 requests slow, not failed. Each waiting S3 request holds its RGW request thread meanwhile.
- **`503` is worth sending.** transhim answers `503` for an `UpstreamError` marked `Retryable`. That reaches the S3 client as `503 ServiceUnavailable`, which S3 SDKs retry.
- **A `403` is visible as such.** An authorizer that denies a key by name shows up as `403 AccessDenied` at the S3 client.
- **SSE-S3 key operations.** If `POST keys/{name}` fails, the PutObject that needed the key fails (`500`) and stores nothing. If `config` or `DELETE` fail, DeleteBucket succeeds all the same and the key is orphaned, as described above.
- Unencrypted objects are not affected by any of this.

## Other clients

### sops

[sops](https://github.com/getsops/sops) with a `hc_vault_transit` key works against transhim. Observed with sops 3.13.3 (`integration/`, `TestSops` and `TestSopsFailures`); what it sends to OpenBao 2.7.2 was recorded with `tools/vaultrec` (sops 3.12.2) and is the same.

```console
$ export VAULT_TOKEN=...   # what the server's authorizer expects
$ sops encrypt --hc-vault-transit https://transhim.example.com:8200/v1/transit/keys/my-key secrets.yaml > secrets.enc.yaml
$ sops decrypt secrets.enc.yaml
```

- **The key URI** is the server's address, the mount's prefix, `/keys/`, and the key name. sops takes what stands between `/v1/` and `/keys/` as the engine path, so the mount's prefix must start with `/v1/`.
- **What it calls.** `PUT {prefix}/encrypt/{name}` with `{"plaintext":"<base64 of a 32 byte data key>"}` when a file is encrypted, `PUT {prefix}/decrypt/{name}` with `{"ciphertext":"vault:v1:..."}` when it is decrypted; `sops rotate` does both. Nothing else: no `keys/`, `auth/`, or `sys/` call. It reads `data.ciphertext` and `data.plaintext`, and stores the ciphertext in the file as it is.
- **It uses Vault's Go client**: `PUT` instead of `POST`, an `X-Vault-Request: true` header, no `Content-Type`, the token from `VAULT_TOKEN` or `~/.vault-token`.
- **No context.** The ciphertext is bound to the mount ID and the key name only.
- **The key must exist.** With `encrypt` on a missing key, Vault creates the key; transhim answers `400 encryption key not found`, and sops fails with that message.
- **Errors reach the user.** sops prints the status and transhim's message (`Code: 403. Errors: * permission denied`).
- **`5xx` is retried.** Vault's Go client sends a request up to three times, about three seconds in all, when the answer is `502` or `503`. A failing key service therefore gets three calls per sops invocation.

### RustFS

[RustFS](https://github.com/rustfs/rustfs) with its `vault-transit` KMS backend **does not work against transhim**, and cannot with transhim alone: it needs a KV v2 secrets engine at the same address. Observed with RustFS 1.0.6 (§12 item 5).

How it was looked at: RustFS in a container (`RUSTFS_KMS_ENABLE=true`, `RUSTFS_KMS_BACKEND=vault-transit`, `RUSTFS_KMS_VAULT_ADDRESS`, `RUSTFS_KMS_VAULT_TOKEN`; the Transit mount defaults to `transit`), first with `tools/vaultrec` in front of OpenBao 2.7.2, then pointed at a transhim server. Source references are to `crates/kms/src/backends/vault_transit.rs` at the tag `1.0.6`.

What RustFS sends to OpenBao:

| request | sent when | against transhim |
|---|---|---|
| `GET /v1/auth/token/lookup-self` | at startup | `404`. RustFS goes on without it (it then does not renew the token) |
| `LIST {prefix}/keys` | at startup, as the health check, and again later | `404 unsupported path`. **RustFS does not start**: only a `404` without a message, as Vault gives for an empty mount, passes. Nothing below was reached |
| `GET {prefix}/keys/{name}` | before a key is used for the first time, and again later | would be `404`, which RustFS takes as a missing key (`KMS.NotFoundException`) |
| `GET` and `POST /v1/secret/data/rustfs/kms/transit-metadata/{name}` | with the first use of a key: RustFS keeps a record per key (state, usage, tags) in KV v2 and creates it with check-and-set | not Transit, and not served. The write is mandatory: by the source, a key is not used if it fails |
| `POST {prefix}/keys/rustfs-internal-kms-probe` with `{"type":"aes256-gcm96"}` | at startup: a key of its own for the health probe | would be accepted |
| `POST {prefix}/encrypt/{name}` with `{"plaintext":"...","associated_data":"..."}` | an encrypted object is written | **`associated_data` is ignored**; see below |
| `POST {prefix}/decrypt/{name}` with `{"ciphertext":"...","associated_data":"..."}` | an encrypted object is read | |

What that shows:

- **No `datakey`.** RustFS makes the data key itself and wraps it with `encrypt`, as sops does. Keys are not created on demand: an S3 request naming a key that Transit does not have fails with `KMS.NotFoundException`. SSE-S3 uses the default key, named `default` unless `RUSTFS_KMS_DEFAULT_KEY_ID` is set.
- **The object is bound with `associated_data`, not `context`.** Its value is the base64 of a JSON object: `{"<bucket>":"<bucket>/<object>"}`, plus the client's `x-amz-server-side-encryption-context` entries. transhim ignores the field, so against transhim that binding would be silently lost: a ciphertext would decrypt for any object. This has to be closed before RustFS is served at all.
- **It reads key metadata.** `GET keys/{name}` is deserialized into the full shape of Vault's answer (`type`, `keys`, `latest_version`, and so on), and the source has calls for `rotate`, `rewrap`, `config`, and `DELETE` as well, for its key management API.
- **Requests** come from the Rust client `vaultrs`: `POST` and `LIST`, an `X-Vault-Request: true` header, no `Content-Type`.

To serve RustFS, transhim would need `LIST keys`, `GET keys/{name}` in Vault's shape, and `associated_data` bound into ciphertexts, and the deployment would still need a real Vault or OpenBao for the KV v2 records, with a proxy sending the Transit paths to transhim. None of this exists.

## Not covered yet

- §12 item 3 (go-kms-wrapping): deferred with its clients (DESIGN.md §3, D9).
