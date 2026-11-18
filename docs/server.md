# Writing a server with transhim

transhim is a library: you write the `main`, the backend for your KMS, and the rules for who may use which key. This guide covers what that takes for a server you can run in production. For the Ceph RGW side, see [rgw.md](rgw.md).

The examples ([awskms](../examples/awskms), [sakurakms](../examples/sakurakms), [sqlkeystore](../examples/sqlkeystore)) are working code for most of what follows. Their servers keep the per-bucket keys in memory, which this guide replaces.

## The parts

```go
func run(ctx context.Context) error {
	// 1. A backend for your KMS (see "Writing a backend").
	kmsBackend := newMyKMS()

	// 2. For per-bucket keys (SSE-S3): a durable KeyStore and the
	//    hierarchical backend over one root key in the KMS.
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	store, err := sqlkeystore.New(db, sqlkeystore.PostgreSQL)
	if err != nil {
		return err
	}
	sseS3, err := hierarchical.New(kmsBackend, "transhim-root", store)
	if err != nil {
		return err
	}

	// 3. The server: mounts, authorization, cache, audit.
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/transit-kms", "rgw-kms", kmsBackend),
		transhim.Mount("/v1/transit-sse-s3", "rgw-sse-s3", sseS3),
		transhim.WithAuthorizer(authorize),
		transhim.WithDecryptCache(transhim.DecryptCacheConfig{
			MaxEntries: 10000,
			TTL:        5 * time.Minute,
		}),
		transhim.WithAuditHook(audit),
	)
	if err != nil {
		return err
	}

	// 4. An http.Server of your own: TLS, health check, shutdown.
	hs := &http.Server{
		Addr:              ":8200",
		Handler:           withHealthCheck(srv),
		ReadHeaderTimeout: 10 * time.Second,
	}
	// ... ListenAndServeTLS, and Shutdown when ctx is done
}
```

`*transhim.Server` is an `http.Handler`. It serves the Transit API below its mounts and answers `404` for everything else. Listening, TLS, and shutdown are yours.

## Decisions you cannot change later

These are bound into the ciphertexts that Ceph stores with every object. Changing one makes the existing objects unreadable.

- **The mount ID** (`rgw-kms`, `rgw-sse-s3` above). The prefix, in contrast, is routing only and can change at any time.
- **How your backend binds the AAD**, and which KMS key a key name resolves to.
- **The root key of a hierarchical backend**: the name you pass to `hierarchical.New` and the KMS key it resolves to.

Choose them once, write them down, and treat them like a schema.

There is no way to read ciphertexts made by Vault or OpenBao. Objects that RGW encrypted through another Transit server stay unreadable after a switch to transhim, and RGW talks to one endpoint at a time. Copy such objects out before switching.

## Writing a backend

A backend is two methods:

```go
type Backend interface {
	Encrypt(ctx context.Context, req EncryptRequest) (WrappedKey, error)
	Decrypt(ctx context.Context, req DecryptRequest) ([]byte, error)
}
```

It wraps small blobs: data keys of 16 to 64 bytes for `datakey`, and up to the mount's plaintext limit for `encrypt` (`WithMaxPlaintextSize`, default 4096 bytes; lower it if your KMS takes less). It must be safe for concurrent use and must not keep `req.Plaintext`, which the server zeroes after the call.

### Bind the AAD

`req.AAD` carries the mount ID, the key name, and the client's context. The backend must make sure that a ciphertext made with one AAD does not decrypt with another. Without that, an S3 user could have RGW decrypt another object's data key by naming a different key or context. There are two ways:

- **The KMS has a parameter for it** (additional authenticated data, an encryption context): pass the AAD or a hash of it. The AWS KMS example passes `{"transhim-aad": hex(sha256(AAD))}` as encryption context.
- **The KMS has none**: put a hash of the AAD in front of the plaintext, encrypt both, and compare the hash after decrypting, before returning anything. This is only sound if the KMS ciphertext is authenticated. The SAKURA Cloud KMS example does this.

`transhimtest.RunConformance` fails a backend that does not bind the AAD.

### `KeyRef` and `Version`

Both are part of the `WrappedKey` that `Encrypt` returns. The server puts them into the ciphertext string and hands them back on decrypt. **It does not authenticate them: a client can change them in a ciphertext.**

- **`Version`** is the `N` of `vault:vN:...` and the `key_version` of the answer. It is there because the Vault format has it. Unless your backend keeps several generations of a key itself, it has no use: return `1`, and reject anything else on decrypt with `ErrCiphertextMismatch`. A KMS that rotates keys internally, like the two in the examples, needs no version here.
- **`KeyRef`** is a free-form string: by convention the exact key that was used, such as a KMS key ARN. Reading it out of a ciphertext tells an operator which KMS key an object depends on, for example after an alias was moved. The examples record it and do not look at it on decrypt.

Uses that change what decrypt does:

- a backend that rotates keys itself selects the generation by `Version` or `KeyRef`;
- a KMS that must be told the key or key version to decrypt with gets it from `KeyRef`;
- a backend that changes how it builds the blob tells old from new by either.

These are sound on one condition: the value only selects among the keys that `req.KeyName` may use anyway, and decrypting with the wrong one fails. Never take `KeyRef` as the KMS key to use as it is. That would let a client point the server at any key its credentials reach.

### Decide what a key name may reach

RGW passes the key ID of an S3 request on unchecked, so a backend that hands the name straight to the KMS lets every S3 user use every key the server's credentials can. Resolve names inside a namespace of their own (an alias prefix, an explicit list) and answer `ErrKeyNotFound` for the rest. Key names are opaque strings without `/` and control characters; do not assume more.

### Map errors

The server answers by the sentinel error a backend error wraps. Details stay in the log and the audit event and never reach the client.

| the KMS says | return | transhim answers | S3 client sees (Ceph 19, 20) |
|---|---|---|---|
| no such key | `ErrKeyNotFound` | `400` | `400 InvalidArgument` |
| ciphertext does not verify | `ErrCiphertextMismatch` | `400` | `400 InvalidArgument` |
| access denied, key disabled | `ErrPermissionDenied` | `403` | `403 AccessDenied` |
| throttled, unavailable, no answer | `&UpstreamError{Err: err, Retryable: true}` | `503` | `503 ServiceUnavailable` |
| any other failure | `ErrUpstream` | `502` | `500 InternalError` |
| (an error wrapping none of these) | | `500` | `500 InternalError` |

Mark what is temporary as retryable: the S3 client then gets a `503 ServiceUnavailable`, which tells it to try again, instead of an unspecific `500`. (Ceph 18 answers `500` in both cases.) Never report an outage as `ErrKeyNotFound`: for a per-bucket key that reads as "the bucket's key is gone".

### Set a time limit

**The server puts no deadline on backend calls, and neither does RGW.** A KMS call that hangs keeps an RGW request thread waiting for as long as it hangs. With the decrypt cache enabled, and for key loads of the hierarchical backend, the call does not even end when the client goes away, because other requests may be waiting for its result.

Give every KMS call a time limit, in the KMS client or around the backend, and report a timeout as retryable:

```go
type timeLimit struct {
	transhim.Backend
	d time.Duration
}

func (b timeLimit) Encrypt(ctx context.Context, req transhim.EncryptRequest) (transhim.WrappedKey, error) {
	ctx, cancel := context.WithTimeout(ctx, b.d)
	defer cancel()
	wk, err := b.Backend.Encrypt(ctx, req)
	return wk, timedOut(err)
}

func (b timeLimit) Decrypt(ctx context.Context, req transhim.DecryptRequest) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, b.d)
	defer cancel()
	plaintext, err := b.Backend.Decrypt(ctx, req)
	return plaintext, timedOut(err)
}

func timedOut(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &transhim.UpstreamError{Err: err, Retryable: true}
	}
	return err
}
```

A wrapper like this hides the optional interfaces below. If the wrapped backend has them, forward them too. Do the same for the database behind a `KeyStore`.

### Optional interfaces

- `DataKeyGenerator`: implement it if the KMS has a "generate data key" call. Otherwise the server generates data keys itself and wraps them with `Encrypt`.
- `KeyLifecycle`: implement it to create and delete keys when the client asks. RGW does for SSE-S3, one key per bucket. Usually you do not implement this yourself but use the hierarchical backend. Without it, key requests succeed and do nothing; `RejectUnmanagedKeyOps` on the mount answers them with `405` instead.

### Test it

```go
func TestServer(t *testing.T) {
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/transit", "test", backend),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer("token")),
	)
	if err != nil {
		t.Fatal(err)
	}
	transhimtest.RunConformance(t, transhimtest.Conformance{
		Handler: srv, Prefix: "/v1/transit", Token: "token",
		KeyNames: [2]string{"key-1", "key-2"}, // must exist in the KMS
	})
}
```

It drives every endpoint the way RGW does, including the requests that must be rejected: a ciphertext presented under another key name or context, and tampered ciphertexts. Run it against an emulator of your KMS if there is one. `transhimtest.FakeBackend` is an in-memory backend for the tests of everything else.

## Authorization

An `Authorizer` is called for every request, before the backend and before the decrypt cache:

```go
type Authorizer func(ctx context.Context, req AuthRequest) error
```

`AuthRequest` has the operation, the mount ID, the key name, the context, the token, and the TLS state. It does not say which S3 user is behind the request: RGW does not pass that on. What you can decide is what RGW as a whole may do.

The authorizer runs after the request body was read and before anything in it is reported as wrong: a client that is refused gets a `403` whatever it sent.

### Where the token comes from

`AuthRequest.Token` is the value of the request's `X-Vault-Token` header, as in the Vault API, or `""` if there is none. transhim does not interpret it: there are no Vault tokens to issue or look up, and what a valid token is, is up to the authorizer. (`AuthRequest.Namespace` is the `X-Vault-Namespace` header, passed on the same way.)

RGW reads the token from a file and sends it with every request:

```ini
[client.rgw]
rgw_crypt_vault_auth = token
rgw_crypt_vault_token_file = /etc/ceph/transhim.token

rgw_crypt_sse_s3_vault_auth = token
rgw_crypt_sse_s3_vault_token_file = /etc/ceph/transhim.token
```

```console
$ openssl rand -hex 32 > /etc/ceph/transhim.token
$ chown ceph:ceph /etc/ceph/transhim.token && chmod 600 /etc/ceph/transhim.token
```

- The file must be readable by the user RGW runs as and by nobody else, or RGW refuses to use it.
- The server must expect the same value. The examples read it from a copy of that file (`-token-file`) and trim surrounding whitespace, since the file usually ends with a newline.
- The two mounts can share a token or have one each. With one each, the authorizer can tell from the token which of RGW's two uses a request belongs to, and check that it matches `req.MountID`.
- RGW before umbrella sends the header twice with the same value; transhim uses the first.

See [rgw.md](rgw.md) for the rest of RGW's settings.

### The context

`AuthRequest.Context` is the decoded `context` of a datakey, encrypt, or decrypt request: the bytes that are bound into the ciphertext along with the mount ID and the key name. It is nil for key operations and when the request has none.

RGW sends a JSON object that names the S3 object:

```json
{"aws:s3:arn":"arn:aws:s3::<owner>:<bucket>/<object>"}
```

How far that can be trusted depends on the mount:

- **SSE-S3**: the context is RGW's own. RGW rejects a PutObject that brings an encryption context. An authorizer can tell the bucket and the object from it.
- **SSE-KMS**: the S3 user can add entries with `x-amz-server-side-encryption-context`, and an `aws:s3:arn` entry there **replaces** RGW's. The user can name any object. Do not let the context decide which key an S3 user may use; a rule like "this key only for that bucket" cannot be enforced this way.

In both cases it is worth logging; see the audit hook below.

### An authorizer

`transhim.StaticTokenAuthorizer(token)` allows everything to one token. A server usually wants more:

```go
func authorize(ctx context.Context, req transhim.AuthRequest) error {
	// Several tokens, so that one can be replaced without downtime: add the
	// new one, change RGW's token file, remove the old one.
	if !tokenOK(req.Token) {
		return transhim.ErrPermissionDenied
	}
	switch req.MountID {
	case "rgw-kms":
		// S3 users choose this name. Nobody deletes or creates keys here.
		if req.Op != transhim.OpDataKey && req.Op != transhim.OpDecrypt {
			return transhim.ErrPermissionDenied
		}
		if !allowedKeys[req.KeyName] {
			return fmt.Errorf("%w: key %q", transhim.ErrPermissionDenied, req.KeyName)
		}
	case "rgw-sse-s3":
		// RGW chooses these names (one per bucket) and manages the keys.
	}
	return nil
}

func tokenOK(token string) bool {
	got := sha256.Sum256([]byte(token))
	ok := 0
	for _, want := range tokenHashes { // [][sha256.Size]byte
		ok |= subtle.ConstantTimeCompare(got[:], want[:])
	}
	return ok == 1
}
```

- Compare tokens in constant time, as above.
- Return an error wrapping `ErrPermissionDenied` to answer `403`. RGW shows it to the S3 client as `403 AccessDenied`.
- A backend can also refuse key names, but it is not called for decrypts answered from the cache. Rules that must hold for every request belong here.
- For mutual TLS, set `ClientAuth: tls.RequireAndVerifyClientCert` and `ClientCAs` in the `http.Server`'s `TLSConfig`, and check `req.TLS.VerifiedChains[0][0]` (its subject or SANs) in the authorizer. RGW's side is `rgw_crypt_vault_ssl_clientcert` and `rgw_crypt_vault_ssl_clientkey`.
- `transhim.AllowUnauthenticated()` builds a server without an authorizer. Such a server hands data keys to anyone who can reach it.

## Per-bucket keys

For SSE-S3, RGW creates one key per bucket and deletes it with the bucket. A KMS key per bucket is usually too slow and too expensive. `hierarchical.Backend` keeps one root key in the KMS and gives every key name a random intermediate key, stored wrapped by the root key in a `KeyStore`:

```go
sseS3, err := hierarchical.New(
	kmsBackend,      // root backend
	"transhim-root", // the only key name the root backend ever sees
	store,           // a hierarchical.KeyStore
)
```

- **The `KeyStore` is state you must not lose.** A lost entry makes every object of that bucket unreadable. The entries are wrapped, so the store need not be secret, but it must be durable, consistent, and backed up. `keystore/memstore` is for tests only.
- [examples/sqlkeystore](../examples/sqlkeystore) is a store on PostgreSQL or SQLite to start from; its README lists what to take care of. `transhimtest.RunKeyStoreConformance` checks a store of your own against the contract. It cannot check durability.
- A store that is down must report `ErrUpstream` (retryable), never `ErrKeyNotFound`.
- Deleting a key deletes its intermediate key, which makes the bucket's data unreadable for good (crypto-shredding). RGW does not always delete the key of a deleted bucket, so orphaned keys can stay in the store; see [rgw.md](rgw.md).
- Unwrapped intermediate keys are cached in memory (`hierarchical.WithKeyCacheTTL`, default 5 minutes). Loading one costs a `KeyStore` read and a KMS call; requests for the same key that arrive meanwhile wait for that load.

### Rotating the root key

Rotation inside the KMS that keeps the key's identity (automatic rotation in AWS KMS, key rotation in SAKURA Cloud KMS) needs nothing from transhim: old wrapped keys keep decrypting.

Moving to a different root key is not supported by any tool. It means unwrapping every stored key with the old root key, wrapping it with the new one, and replacing the entries directly in the store, with all instances stopped. The intermediate keys themselves are never rotated: a bucket keeps its key for life.

## Caches and limits

### The decrypt cache

RGW calls `decrypt` on every read of an encrypted object, including HeadObject and each part of a multipart upload, always with the same wrapped key. `WithDecryptCache` answers those from memory:

```go
transhim.WithDecryptCache(transhim.DecryptCacheConfig{
	MaxEntries:    10000,
	TTL:           5 * time.Minute,
	WarmOnDatakey: true,
})
```

- It is off by default. Enable it unless your KMS is fast and cheap.
- Identical decrypts that arrive together share one KMS call.
- `WarmOnDatakey` also stores the keys handed out by `datakey`. RGW decrypts the data key of a multipart upload right after it got it; with a slow KMS this saves that call.
- Both `MaxEntries` and `TTL` are required. An entry holds one data key.

### What the TTLs mean for revocation

Both caches (the decrypt cache, and the intermediate key cache of the hierarchical backend) hold key material in memory. A key deleted through an instance is dropped from that instance's caches at once. What happens behind the server's back takes up to the TTL to become effective:

- disabling or deleting a key directly in the KMS,
- deleting a key through another instance.

Choose the TTLs as the longest time you accept for such a revocation. A key name that your authorizer stops allowing is refused at once: the authorizer runs on every request, before the caches.

### Other options

| option | default | when to change it |
|---|---|---|
| `WithMaxPlaintextSize` (mount) | 4096 bytes | your KMS encrypts less; only the `encrypt` endpoint is affected, which RGW does not use |
| `WithMaxBodySize` | 1 MiB | rarely |
| `WithBodyReadTimeout` | 10 s | rarely. It limits how long a client may take to send its body, which is read before the request is authorized; a client that is too slow gets `408` |
| `RequireDeletionAllowed` (mount) | off | to refuse `DELETE keys/{name}` unless the client set `deletion_allowed` first, as Vault does. RGW sets it. The flag is kept in memory only |
| `RejectUnmanagedKeyOps` (mount) | off | to answer key requests with `405` on a mount whose keys are provisioned by hand. Do not use it on a mount RGW uses for SSE-S3 |
| `WithLogger` | `slog.Default()` | to send the server's own log elsewhere |

## Running it

### TLS and the HTTP server

The Transit datakey API returns data keys in plaintext, so serve TLS and let only RGW reach the server.

In the `http.Server`, set `ReadHeaderTimeout`. The server limits the time for the body itself (`WithBodyReadTimeout`) and lifts that limit, and one set by `ReadTimeout`, once the body is read, so that it does not cut off a slow KMS call. If you set `WriteTimeout`, make it longer than your slowest KMS call plus its retries: a response cut off by it reaches the S3 client as a `500`. On shutdown, give `Shutdown` at least that long as well.

### Health checks

The server answers nothing outside its mounts. Add a health check in front of it:

```go
func withHealthCheck(srv http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		srv.ServeHTTP(w, r)
	})
}
```

Keep it cheap. A check that calls the KMS on every probe costs a KMS call each time, and takes an instance out of service for an outage that affects all instances alike.

### Audit, logs, and metrics

`WithAuditHook` calls a function after every request, including rejected ones:

```go
func audit(ctx context.Context, ev transhim.AuditEvent) {
	attrs := []any{
		"op", string(ev.Op), "mount_id", ev.MountID, "key_name", ev.KeyName,
		"context", string(ev.Context), // with RGW: the S3 object, as JSON
		"status", ev.Status, "cache_hit", ev.CacheHit, "duration", ev.Duration,
		"remote_addr", ev.RemoteAddr, "request_id", ev.RequestID,
	}
	if ev.Err != nil {
		attrs = append(attrs, "error", ev.Err.Error())
	}
	slog.InfoContext(ctx, "audit", attrs...)
}
```

- The hook runs synchronously and must not block. Hand events to a queue if the sink can be slow.
- `ev.Err` is where the reason of a failure is: the KMS error your backend wrapped. The client only got the status.
- `ev.Context` says which S3 object a request was for, also for requests that were refused or answered from the cache. With SSE-KMS it is what the S3 user claims (see "The context" above): a record, not proof.
- Events never contain key material, ciphertexts, or tokens. The server's own log has none of these and no context either. Key names are logged; with RGW they are KMS key IDs and bucket IDs.
- There is no metrics exporter. Count in the hook: requests by `Op`, `MountID`, and `Status`, the `Duration`, and the share of `CacheHit` among decrypts. Do not use the key name as a label: there is one per bucket.

What to alert on: `5xx` answers (every one is a failed S3 request), a rising duration (RGW waits without limit), and `403` answers that you do not expect.

### Several instances

The only state is the `KeyStore`. Several instances can serve the same RGW behind a load balancer if they share the `KeyStore` and use the same mount IDs, root key, and backend configuration. The caches are per instance; see the TTLs above.

### Before going live

- [ ] Mount IDs, AAD binding, and root key are decided and written down.
- [ ] `RunConformance` passes on a server built the way production is.
- [ ] The `KeyStore` is durable and backed up, restoring it has been tried, and `RunKeyStoreConformance` passes.
- [ ] Every KMS and database call has a time limit.
- [ ] Outages are answered with `503`, never with "key not found".
- [ ] The authorizer limits which key names the SSE-KMS mount accepts.
- [ ] TLS is on, and only RGW can reach the server.
- [ ] The audit hook logs, and `5xx` answers raise an alert.
- [ ] The cache TTLs are the revocation delay you accept.
- [ ] An object written with SSE-KMS and one with SSE-S3 can be read back after a restart of every instance.
