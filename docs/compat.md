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
| Ceph RGW | 18.2.8 (reef), 19.2.7 (squid), 20.2.5 (tentacle) |
| reference Transit | OpenBao 2.7.2, dev mode |
| S3 client | aws-cli 2.36.44 |

The capture files contain plaintext data keys. They belong to a throwaway dev server that no longer exists. The Vault token is redacted by the recorder.

Source references are to `src/rgw/rgw_kms.cc` and `src/rgw/rgw_crypt.cc` in the Ceph repository at the release tags above.

## §12 item 1: what RGW sends

RGW calls exactly these five endpoints, on all three releases. It never calls `encrypt`, `GET keys/{name}`, `auth/token/*`, or `sys/*`.

| request | body | sent when |
|---|---|---|
| `POST {prefix}/datakey/plaintext/{name}` | `{"context":"<base64>"}` | an encrypted object is written: PutObject, CreateMultipartUpload, CopyObject destination |
| `POST {prefix}/decrypt/{name}` | `{"context":"<base64>","ciphertext":"vault:v1:..."}` | an encrypted object is read: GetObject (also ranged), HeadObject, each UploadPart, CopyObject source; on tentacle also CompleteMultipartUpload |
| `POST {prefix}/keys/{name}` | `{"type":"chacha20-poly1305","derived":true}` | SSE-S3 only: the first encrypted write to a bucket |
| `POST {prefix}/keys/{name}/config` | `{"deletion_allowed":true}` | SSE-S3 only: DeleteBucket of a bucket that has a key |
| `DELETE {prefix}/keys/{name}` | none | SSE-S3 only: right after `config` |

Details that matter to an implementation:

- **Headers.** RGW sends `Accept: */*`, `Content-Length`, and `X-Vault-Token`. There is **no `Content-Type`**. `X-Vault-Token` is sent **twice** with the same value (a duplicated `append_header` call; fixed on Ceph `main`, still present in 20.2.5). A server must take the first value and must not require a content type.
- **Methods.** Only `POST` and `DELETE`. `PUT` is never used.
- **`context`** is always present. It is the base64 of a JSON object: `{"aws:s3:arn":"arn:aws:s3::<owner>:<bucket>/<object>"}`, plus the client's `x-amz-server-side-encryption-context` entries if any. RGW stores it with the object and sends the identical value on every decrypt. CopyObject decrypts with the source object's context and requests a new data key with the destination's.
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
| 18.2.8, 19.2.7 | logs an error, continues | **treats it as a failure and never sends `DELETE`** |
| 20.2.5 | logs an error, continues | continues |

With a current OpenBao, reef and squid therefore never delete a bucket key: it stays behind with `deletion_allowed` set. This is visible in `ceph-v18.2.8.jsonl` and `ceph-v19.2.7.jsonl` (three `config` calls, no `DELETE`).

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

- **Decrypt volume.** RGW calls `decrypt` for every read of an encrypted object, including HeadObject and every part of a multipart upload. A 1000-part upload is 1000 decrypt calls for the same wrapped key. This is the case the decrypt cache (DESIGN.md §9) exists for.
- **CopyObject of an encrypted object** answers `501 NotImplemented` on reef and squid, before any Vault call. It works on tentacle. This is RGW's own limitation.
- **Token file.** RGW reads the token from a file that group and others must not be able to access (reef, squid; tentacle allows up to `0740`). `docker/ceph-demo.sh` writes it as the `ceph` user for that reason.
- **aws CLI.** aws-cli 2.36 crashes while printing an RGW error whose `<Message>` is empty (reef and squid send those). The capture script reads the status and error code from the wire instead.

## How RGW reacts to a failing Transit endpoint

Observed with the acceptance test (`integration/`, `TestRGWFaults` and `TestRGWEndpointDown`), which puts a fault in front of transhim for one kind of request at a time. The S3 operations are PutObject (fails in `datakey`) and GetObject (fails in `decrypt`) with SSE-KMS; both react the same way.

| Transit endpoint answers | S3 client sees (tentacle, squid) | S3 client sees (reef) |
|---|---|---|
| `400` (missing key, invalid ciphertext) | `400 InvalidArgument` | `400 InvalidArgument` |
| `403` | `403 AccessDenied` | `403 AccessDenied` |
| `500` | `500 InternalError` | `500 UnknownError` |
| `502` | `500 InternalError` | `500 UnknownError` |
| `503` | `503 ServiceUnavailable` | `500 UnknownError` |
| `200` without `data`, or not JSON | `400 InvalidArgument` | `400 InvalidArgument` |
| connection reset, or nothing listening | `500 InternalError` | `500 UnknownError` |
| answer after 3 s, or after 75 s | success | success |

What follows from it:

- **RGW fails closed.** In none of these cases was an object stored unencrypted or handed out. A PutObject whose `datakey` failed leaves no object behind.
- **RGW does not retry**, and it sets no timeout that 75 seconds would reach: a slow key service makes S3 requests slow, not failed. Each waiting S3 request holds its RGW request thread meanwhile.
- **`503` is worth sending.** transhim answers `503` for an `UpstreamError` marked `Retryable`. On squid and tentacle that reaches the S3 client as `503 ServiceUnavailable`, which S3 SDKs retry.
- **A `403` is visible as such.** An authorizer that denies a key by name shows up as `403 AccessDenied` at the S3 client.
- **SSE-S3 key operations.** If `POST keys/{name}` fails, the PutObject that needed the key fails (`500`) and stores nothing. If `config` or `DELETE` fail, DeleteBucket succeeds all the same and the key is orphaned, as described above.
- Unencrypted objects are not affected by any of this.

## Not covered yet

- §12 items 3 and 5 (go-kms-wrapping, RustFS): deferred with their clients (DESIGN.md §3, D9).
