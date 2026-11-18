# Using transhim with Ceph RGW

This guide configures Ceph RGW server-side encryption (SSE-KMS and SSE-S3) against a transhim server. It applies to Ceph 19 (squid), 20 (tentacle), and 21 (umbrella), the releases transhim is tested with. What RGW sends, and how it reacts when things fail, is recorded in [compat.md](compat.md).

## The two mounts

RGW uses a Transit endpoint in two independent ways. Give each its own mount.

| | SSE-KMS | SSE-S3 |
|---|---|---|
| S3 request | `x-amz-server-side-encryption: aws:kms` with a key ID | `x-amz-server-side-encryption: AES256`, or a bucket default |
| key name RGW sends | the key ID of the S3 request | one per bucket (the bucket ID by default) |
| who creates keys | you, in the KMS | RGW, on the first encrypted write to a bucket |
| who deletes keys | you | RGW, when the bucket is deleted |
| transhim backend | your KMS backend | `hierarchical.Backend` over your KMS backend |

A server for both, as in [examples/awskms](../examples/awskms):

```go
srv, err := transhim.NewServer(
	transhim.Mount("/v1/transit-kms", "rgw-kms", kmsBackend),
	transhim.Mount("/v1/transit-sse-s3", "rgw-sse-s3", sseS3Backend), // a hierarchical.Backend
	transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(token)),
	transhim.WithDecryptCache(transhim.DecryptCacheConfig{MaxEntries: 10000, TTL: 5 * time.Minute}),
)
```

The mount IDs (`rgw-kms`, `rgw-sse-s3`) are bound into every ciphertext. Choose them once and never change them. The prefixes can change at any time, as long as RGW's `*_vault_prefix` settings follow.

## RGW configuration

```ini
[client.rgw]
# SSE-KMS
rgw_crypt_s3_kms_backend = vault
rgw_crypt_vault_secret_engine = transit
rgw_crypt_vault_addr = https://transhim.example.com:8200
rgw_crypt_vault_prefix = /v1/transit-kms
rgw_crypt_vault_auth = token
rgw_crypt_vault_token_file = /etc/ceph/transhim.token
rgw_crypt_vault_ssl_cacert = /etc/ceph/transhim-ca.pem

# SSE-S3
rgw_crypt_sse_s3_backend = vault
rgw_crypt_sse_s3_vault_secret_engine = transit
rgw_crypt_sse_s3_vault_addr = https://transhim.example.com:8200
rgw_crypt_sse_s3_vault_prefix = /v1/transit-sse-s3
rgw_crypt_sse_s3_vault_auth = token
rgw_crypt_sse_s3_vault_token_file = /etc/ceph/transhim.token
rgw_crypt_sse_s3_vault_ssl_cacert = /etc/ceph/transhim-ca.pem
```

Notes on these settings:

- **`secret_engine = transit`, with nothing after it.** RGW also has a legacy mode that exports keys from Vault, which transhim does not serve. RGW uses it only if the prefix ends with `/export/encryption-key` or a `compat=` parameter asks for it. With the prefixes above it is off.
- **`prefix`** must be the mount's prefix exactly.
- **The token file** holds the token the server's authorizer expects. RGW refuses to read it if group or others can access it (tentacle and umbrella accept up to `0740`): make it `0600`, owned by the user RGW runs as.
- **TLS.** `rgw_crypt_vault_verify_ssl` and `rgw_crypt_sse_s3_vault_verify_ssl` default to `true`; keep them. `*_ssl_cacert` is only needed for a private CA. For mutual TLS there are `*_ssl_clientcert` and `*_ssl_clientkey`; the server sees the client certificate in `AuthRequest.TLS`.
- **`rgw_crypt_sse_s3_key_template`** (default `%bucket_id`) sets the per-bucket key name. Leave it alone unless you have a reason: changing it on a running cluster makes RGW ask for keys under new names.
- **`rgw_crypt_require_ssl`** (default `true`) is about the S3 side: RGW rejects SSE requests that reach it over plain HTTP. Turn it off only for tests, or when TLS ends at a proxy in front of RGW.

Data keys cross the wire in plaintext between RGW and transhim; that is how the Transit datakey API works. Run transhim with TLS, and keep it reachable from RGW only.

## What to know before going live

### S3 users choose SSE-KMS keys by name, unchecked

RGW passes the key ID of an S3 request to the Transit endpoint as it is. It does not check whether that S3 user may use that key. With a KMS backend that maps the name straight to a KMS key, every S3 user can use every key the transhim server can use.

Decide what a key name may reach. The usual ways:

- Resolve names within a namespace of their own, so that only keys meant for RGW can be named. The AWS KMS example resolves `name` to the alias `alias/rgw/name`; the SAKURA Cloud KMS example takes an explicit list of names.
- Check the key name in the `Authorizer`. The request does not say which S3 user is asking, so this limits what RGW as a whole may use.

RGW itself rejects key IDs containing `/`.

### Deleting a bucket shreds its SSE-S3 key, usually

When a bucket with an SSE-S3 key is deleted, RGW has the key deleted. With the hierarchical backend, this removes the bucket's intermediate key from the `KeyStore`, and what was encrypted with it cannot be read anymore.

This is best effort. A key stays behind in the `KeyStore` when:

- The backend is read-only (`hierarchical.ReadOnly`): then keys are created and deleted outside the server, see [server.md](server.md#a-server-that-only-reads-the-keystore).
- `DeleteBucketEncryption` was called on the bucket and the bucket was deleted before another SSE-S3 write. RGW then no longer knows the bucket had a key.
- The delete request failed. RGW removes the bucket all the same.

Find orphans by comparing the keys in your `KeyStore` with the bucket markers RGW knows (`radosgw-admin bucket stats`; the default key name is the marker).

On squid (up to 19.2.7 at least), this deletion only works because transhim answers key requests without a body. Against a real Vault or OpenBao that release never deletes a bucket key ([Ceph issue 65626](https://tracker.ceph.com/issues/65626), fixed in tentacle).

### The `KeyStore` is as important as the data

Every SSE-S3 object depends on its bucket's intermediate key in the `KeyStore`. Losing the store loses all of them. The keys in it are wrapped by the KMS root key, so the store does not have to be secret, but it must be durable and backed up. `keystore/memstore` is for tests only. [examples/sqlkeystore](../examples/sqlkeystore) is a store on PostgreSQL or SQLite to start from, and `transhimtest.RunKeyStoreConformance` checks a store of your own.

The root key name and the mount ID are bound into the stored keys. Changing either makes the store unusable.

### Slow or failing KMS

- RGW calls `decrypt` on every read of an encrypted object, including HeadObject and every part of a multipart upload. Enable the decrypt cache (`WithDecryptCache`) unless your KMS is fast and cheap. Requests for the same key that arrive together share one KMS call.
- Umbrella adds a cache of its own for SSE-KMS keys (`rgw_crypt_s3_kms_cache_enabled`, on by default, 60 seconds). It was not seen working in the test setup; see [compat.md](compat.md). Do not count on it in place of the decrypt cache.
- RGW does not time out waiting for the Transit endpoint and does not retry. A slow KMS makes S3 requests slow; each one holds an RGW request thread while it waits.
- RGW fails closed. If the Transit endpoint fails, the S3 request fails, and nothing is stored unencrypted or handed out. The S3 client sees `400 InvalidArgument` for a missing key, `403 AccessDenied` if the authorizer or the KMS denies the request, and `500` or `503` for outages.

### Revocation takes up to the cache TTLs

Two caches hold key material in memory: the decrypt cache of the server, and the intermediate key cache of the hierarchical backend (`WithKeyCacheTTL`). On umbrella, RGW's own SSE-KMS key cache (`rgw_crypt_s3_kms_cache_positive_ttl`, 60 seconds by default) comes on top where it is in effect. A key that is disabled directly in the KMS, or deleted through another transhim instance, stays usable until those entries expire. A key deleted through the same instance is dropped from both at once.

### Several instances

transhim keeps no state besides the `KeyStore`, so several instances can serve the same RGW behind a load balancer, provided they share the `KeyStore` and use the same mount IDs and root key name. The caches are per instance, as described above.

## Checking the setup

```console
$ aws s3api put-object --bucket b --key o --body file \
    --server-side-encryption aws:kms --ssekms-key-id my-key
$ aws s3api put-object --bucket b --key o2 --body file --server-side-encryption AES256
$ aws s3api get-object --bucket b --key o out
```

With an audit hook that logs, the server shows `datakey` on the SSE-KMS mount for the first command; `key_create` and `datakey` on the SSE-S3 mount for the second; and `decrypt` for the third.

If a request fails with `400 InvalidArgument: Failed to retrieve the actual key`, the Transit call failed. The audit event has the reason: an unknown key name, a wrong prefix (`unsupported path` or `no handler for route`), or a wrong token (`permission denied`).

To check your own backend without RGW, run `transhimtest.RunConformance` against a server built on it.
