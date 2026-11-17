# AWS KMS example

An example `transhim.Backend` for AWS KMS (package `awskms`), and an example server for Ceph RGW built on it (`cmd/transhim-awskms`). It is a Go module of its own, so that the AWS SDK is not a dependency of transhim. Copy and adapt it.

## The backend

```go
client := kms.NewFromConfig(awsCfg)
backend := awskms.New(client, awskms.WithAliasPrefix("alias/rgw/"))
```

- `Encrypt` and `Decrypt` call KMS `Encrypt` and `Decrypt`; `datakey` requests use KMS `GenerateDataKey`.
- A key name is resolved to a KMS `KeyId` by `WithKeyID` or `WithAliasPrefix`. The default uses the name as it is.
- KMS keys are not created or deleted by the backend. For per-bucket keys (SSE-S3), it serves as the root of a `hierarchical.Backend`.
- KMS errors are mapped to what the client should see: a missing key to `400 encryption key not found`; a ciphertext that does not verify to `400 invalid ciphertext`; access denied and disabled keys to `403`; throttling and outages to `503`.

Bound into every ciphertext, and therefore not to be changed later:

- The encryption context, `{"transhim-aad": hex(sha256(AAD))}`.
- The KMS key a key name resolves to. `Decrypt` names that key, so KMS refuses ciphertexts of any other key. Moving an alias to another key makes the ciphertexts of the old key undecryptable under that name. Automatic key rotation in KMS is not affected.

The server's IAM role needs `kms:Encrypt`, `kms:Decrypt`, and `kms:GenerateDataKey` on the keys it serves.

## The server

```console
$ aws kms create-alias --alias-name alias/rgw/my-key --target-key-id <key id>       # one per SSE-KMS key ID
$ aws kms create-alias --alias-name alias/transhim-root --target-key-id <key id>    # wraps the per-bucket keys
$ go run ./cmd/transhim-awskms -listen :8200 -token-file token \
    -tls-cert cert.pem -tls-key key.pem
```

| mount | mount ID | used for | key |
|---|---|---|---|
| `/v1/transit-kms` | `rgw-kms` | SSE-KMS | the alias `<-alias-prefix><key ID of the S3 request>`, default prefix `alias/rgw/` |
| `/v1/transit-sse-s3` | `rgw-sse-s3` | SSE-S3 | one intermediate key per bucket, wrapped by `-root-key` (default `alias/transhim-root`) |

The matching RGW configuration is in [docs/rgw.md](../../docs/rgw.md).

**The per-bucket keys are kept in memory** (`keystore/memstore`). When the process ends, every SSE-S3 object becomes unreadable. Before storing anything you need, replace it with a durable `hierarchical.KeyStore`; [examples/sqlkeystore](../sqlkeystore) is one on PostgreSQL or SQLite.

## Tests

```console
$ go test ./...
```

The tests that need a KMS run against the [AWS Emulator](https://github.com/aws/aws-emulator) and are skipped without it:

```console
$ aws-emulator --telemetry off --auth off &
$ export AWS_CA_BUNDLE=$HOME/.aws/emulator/9297/ca.pem
$ TRANSHIM_TEST_KMS_ENDPOINT=https://127.0.0.1:9297 go test ./...
```

They create KMS keys and aliases at that endpoint. Do not point them at a real account.
