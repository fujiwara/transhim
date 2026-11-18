# HTTP API

transhim serves a subset of the [Vault Transit secrets engine API](https://developer.hashicorp.com/vault/api-docs/secret/transit): the endpoints Ceph RGW calls, plus `encrypt`. This page lists them, says what the server does for each, and where that differs from Vault.

For how RGW uses these endpoints, see [compat.md](compat.md). For writing the server, see [server.md](server.md).

## Endpoints

`{prefix}` is the prefix of a mount, for example `/v1/transit-kms`. `{name}` is the key name.

| request | operation | what happens |
|---|---|---|
| `POST {prefix}/datakey/plaintext/{name}` | `datakey` | returns a new data key, in plaintext and wrapped |
| `POST {prefix}/decrypt/{name}` | `decrypt` | unwraps a ciphertext |
| `POST {prefix}/encrypt/{name}` | `encrypt` | wraps a plaintext |
| `POST {prefix}/keys/{name}` | `key_create` | creates the key, if the backend manages keys |
| `POST {prefix}/keys/{name}/config` | `key_config` | accepts `deletion_allowed` |
| `DELETE {prefix}/keys/{name}` | `key_delete` | deletes the key, if the backend manages keys |

`PUT` is accepted wherever `POST` is. The operation names are the values of `transhim.Op`, as authorizers and audit hooks see them.

Not served:

| request | answer |
|---|---|
| `GET {prefix}/keys/{name}` (read a key) | `404` |
| `datakey/wrapped`, `rewrap`, `sign`, `verify`, `hmac`, `random`, `export`, `backup`, and every other Transit path | `404` |
| `LIST {prefix}/keys` | `404` |
| `keys/{name}/rotate`, and anything else below `keys/{name}/` but `config` | `400 invalid key name`: it is read as a key name with a `/` in it |
| `batch_input` in `encrypt` and `decrypt` | ignored: the request is handled as a single one and fails for its missing field |
| anything outside a mount: `/v1/sys/*`, `/v1/auth/*` | `404` |

There are no Vault tokens, policies, or leases. The token is whatever the server's authorizer accepts.

## Common rules

### Requests

- **Routing.** The longest matching mount prefix wins. The prefix is used for routing only; everything else (authorization, the binding of ciphertexts, the audit event) goes by the mount ID.
- **Token.** `X-Vault-Token` is passed to the authorizer. If the header occurs more than once, the first value counts. `X-Vault-Namespace` is passed on as well and not interpreted.
- **Body.** It is parsed as JSON whatever the `Content-Type` is. An empty body is an empty object. Unknown fields are ignored. The limit is 1 MiB (`WithMaxBodySize`), and the client has 10 seconds to send it (`WithBodyReadTimeout`).
- **Key name.** The path segment after the operation, URL-unescaped once, and otherwise an opaque string. It must not be empty and must not contain `/` or control characters.
- **Context.** `context` is base64 of arbitrary bytes. Absent, empty, and decoding to no bytes all mean "no context".

### Order of checks

1. No mount matches the path: `404 no handler for route`.
2. The path below the mount is no operation: `404 unsupported path` (logged as a warning). A known operation with another method: `405` with an `Allow` header.
3. The key name is invalid: `400 invalid key name`.
4. The authorizer refuses: `403 permission denied`. The body has been read by then, but nothing about it is reported before this point.
5. The body cannot be used: `413 request body too large`, `408 request body not received in time`, `400 failed to decode JSON input`, `400 failed to base64-decode context`.
6. The operation itself.

### Answers

Successful answers with data are `200` and have Vault's shape. Only `data` carries anything:

```json
{
  "request_id": "0b9c7f5e-6f0a-4b7e-9d0c-3a1f2e4d5c6b",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": { "...": "..." },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

The key operations answer `204` with no body at all.

Errors have Vault's shape, with one message:

```json
{"errors": ["encryption key not found"]}
```

All answers with a body are `Content-Type: application/json` and `Cache-Control: no-store`.

### Status codes

| status | message | when |
|---|---|---|
| `400` | `encryption key not found` | the backend does not know the key (as Vault answers) |
| `400` | `invalid ciphertext` | the ciphertext is malformed, was tampered with, or was made for another mount, key name, or context. No detail is given |
| `400` | `invalid request`, or one of the messages on this page | the request is wrong |
| `403` | `permission denied` | the authorizer or the backend refuses |
| `404` | `no handler for route`, `unsupported path` | see above |
| `405` | `unsupported operation` | wrong method; or a key operation on a mount with `RejectUnmanagedKeyOps` |
| `408` | `request body not received in time` | |
| `413` | `request body too large` | |
| `500` | `internal error` | an error the backend did not classify |
| `502` | `upstream key service error` | the key service behind the backend failed |
| `503` | `upstream key service error` | the same, and retrying may help |

What a backend or an authorizer reported in detail goes to the log and the audit event, never into the answer.

## `datakey/plaintext/{name}`

Returns a new random data key in plaintext, and the same key wrapped.

| request field | | |
|---|---|---|
| `context` | base64, optional | bound into the ciphertext |
| `bits` | number, optional | `128`, `256` (default), or `512`; anything else is `400 invalid bit length` |

| `data` field | |
|---|---|
| `plaintext` | base64 of the data key, `bits/8` bytes |
| `ciphertext` | the wrapped key, `vault:v1:...` |
| `key_version` | the `N` of `vault:vN:` |

```console
$ curl -s -H "X-Vault-Token: $TOKEN" -d '{"context":"e30="}' \
    https://transhim.example.com:8200/v1/transit-kms/datakey/plaintext/my-key
```

How it is processed:

- If the backend implements `DataKeyGenerator`, it generates and wraps the key in one call (a KMS "generate data key").
- Otherwise the server generates the key with `crypto/rand` and has the backend wrap it with `Encrypt`.
- With `WarmOnDatakey`, the key is also put into the decrypt cache.

A key the backend does not know is `400 encryption key not found`: keys are not created on first use.

## `decrypt/{name}`

Unwraps a ciphertext that `datakey` or `encrypt` returned.

| request field | | |
|---|---|---|
| `ciphertext` | string, required | missing: `400 missing ciphertext to decrypt` |
| `context` | base64, optional | must be the one given when the ciphertext was made |
| `associated_data` | base64 | not supported: `400 associated_data is not supported`, unless it is empty |

| `data` field | |
|---|---|
| `plaintext` | base64 |

How it is processed:

- The ciphertext is decoded (see [Ciphertexts](#ciphertexts)). Anything that is not exactly what the server produced is `400 invalid ciphertext`.
- With the decrypt cache: an identical request (same mount, key name, context, ciphertext) answered before is answered from memory, without calling the backend. Identical requests that arrive at the same time share one backend call.
- Otherwise the backend's `Decrypt` is called. It fails with `400 invalid ciphertext` unless mount, key name, and context are the ones the ciphertext was made with.

## `encrypt/{name}`

Wraps a plaintext. Ceph RGW does not use it.

| request field | | |
|---|---|---|
| `plaintext` | base64, required | missing: `400 missing plaintext to encrypt`. More than the mount's limit (`WithMaxPlaintextSize`, 4096 bytes by default): `400 plaintext too large` |
| `context` | base64, optional | bound into the ciphertext |
| `key_version` | number | not supported: ignored, with a warning in the answer |
| `associated_data` | base64 | not supported: `400 associated_data is not supported`, unless it is empty |

| `data` field | |
|---|---|
| `ciphertext` | `vault:v1:...` |
| `key_version` | the `N` of `vault:vN:` |

The backend's `Encrypt` is called. A key the backend does not know is `400 encryption key not found`.

## `keys/{name}` (create)

Ceph RGW sends this for SSE-S3, on the first encrypted write to a bucket, and again later for a key that exists.

- If the backend implements `KeyLifecycle` (the hierarchical backend does), `CreateKey` is called. A key that exists is left as it is, and the request succeeds. A hierarchical backend with `ReadOnly` creates nothing: a key that does not exist is `400 encryption key not found`.
- Otherwise nothing happens and the request succeeds: keys are expected to exist in the KMS. With `RejectUnmanagedKeyOps` on the mount, the answer is `405` instead.

The answer is `204` without a body. The body fields (`type`, `derived`, and so on) are ignored, except `exportable: true`, which is refused: `400 exportable keys are not supported`.

## `keys/{name}/config`

Accepts `deletion_allowed` (boolean) and ignores every other field. The answer is `204` without a body, also for a key that does not exist.

The flag only matters on a mount with `RequireDeletionAllowed`, where a key can be deleted only after `deletion_allowed` was set to `true`. It is kept in memory: after a restart of the server the client has to set it again. Ceph RGW sets it right before it deletes a key.

## `DELETE keys/{name}`

Ceph RGW sends this for SSE-S3 when a bucket is deleted.

- If the backend implements `KeyLifecycle`, `DeleteKey` is called. With the hierarchical backend this removes the key for good: everything encrypted with it becomes unreadable (with `ReadOnly` the key stays in the store, and only the server forgets it). A key that does not exist is not an error.
- Otherwise nothing is deleted and the request succeeds (or is answered `405` with `RejectUnmanagedKeyOps`).
- In every case the key's entries are removed from the decrypt cache, also if the backend failed.
- On a mount with `RequireDeletionAllowed`: `400 deletion is not allowed for this key` unless the flag was set.

The answer is `204` without a body.

## Ciphertexts

A ciphertext is a string in Vault's form:

```
vault:v1:AQACaDEo...
```

- After `vault:v1:` comes standard base64 of transhim's own envelope, not of anything Vault could read: a format byte, a flags byte, the backend's key reference, and the backend's ciphertext.
- Clients must treat it as opaque and send it back unchanged. Only the exact string the server produced is accepted.
- The ciphertext is bound to the mount ID, the key name, and the context it was made with. Presented under another one, it is refused.
- The version is `1` unless a backend manages key generations itself.
- A ciphertext made by Vault or OpenBao cannot be decrypted, and a ciphertext made by transhim means nothing to Vault.

## Differences from Vault

For a client that only uses the endpoints above, these are the differences in behavior:

| | Vault, OpenBao | transhim |
|---|---|---|
| answer to `keys/{name}` and `keys/{name}/config` | `200` with the key's metadata | `204`, no body. Ceph RGW 19 (squid) needs this to delete bucket keys: it takes a body in the answer to `config` as a failure and then does not send the `DELETE`, a bug in RGW ([compat.md](compat.md)). Encrypting and decrypting are not affected |
| `keys/{name}` with `exportable: true` | accepted | `400` |
| `keys/{name}/config` on a missing key | `400` | `204` |
| `DELETE` of a missing key | `400` | `204` |
| `DELETE` without `deletion_allowed` | `400` | allowed, unless the mount has `RequireDeletionAllowed` |
| `encrypt` on a missing key | creates the key | `400 encryption key not found` |
| `context` on a key that is not derived | ignored | always bound: decrypting needs the same context |
| a key that needs a `context`, without one | `400` | no such requirement |
| wrong key, wrong context, tampered ciphertext | `400` with the cipher's error message | `400 invalid ciphertext` |
| `associated_data` in `encrypt` and `decrypt` | bound into the ciphertext (AEAD key types) | `400 associated_data is not supported`. Use `context`, which transhim always binds |
| key types, `convergent_encryption`, `nonce` | supported | ignored |
| key versions, rotation, `min_decryption_version` | supported | not there; rotation is the KMS's business |

The reference answers were recorded from OpenBao 2.7.2 (see [compat.md](compat.md)).
