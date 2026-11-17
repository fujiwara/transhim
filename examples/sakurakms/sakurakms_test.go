package sakurakms_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ogen "github.com/ogen-go/ogen/validate"
	"github.com/sacloud/sacloud-sdk-go/api/kms"
	v1 "github.com/sacloud/sacloud-sdk-go/api/kms/apis/v1"
	"github.com/sacloud/sacloud-sdk-go/common/saclient"
	mock "github.com/sacloud/sakumock/kms"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/examples/sakurakms"
	"github.com/fujiwara/transhim/hierarchical"
	"github.com/fujiwara/transhim/keystore/memstore"
	"github.com/fujiwara/transhim/transhimtest"
)

// The tests run against sakumock's KMS (https://github.com/sacloud/sakumock),
// started in-process. No SAKURA Cloud account is involved.

type env struct {
	t   *testing.T
	api kms.KeyAPI
	// calls counts the encrypt and decrypt calls that reached the mock.
	calls atomic.Int32
}

// countingClient counts the KMS calls the backend makes.
type countingClient struct {
	kms.KeyAPI
	calls *atomic.Int32
}

func (c countingClient) Encrypt(ctx context.Context, id string, plain []byte, algo v1.EncryptionRequestAlgo) (string, error) {
	c.calls.Add(1)
	return c.KeyAPI.Encrypt(ctx, id, plain, algo)
}

func (c countingClient) Decrypt(ctx context.Context, id, cipher string) ([]byte, error) {
	c.calls.Add(1)
	return c.KeyAPI.Decrypt(ctx, id, cipher)
}

func newEnv(t *testing.T, cfg mock.Config) *env {
	t.Helper()
	srv := mock.NewTestServer(cfg)
	t.Cleanup(srv.Close)
	var sa saclient.Client
	if err := sa.SetEnviron([]string{
		"SAKURA_ENDPOINTS_KMS=" + srv.TestURL(),
		"SAKURA_ACCESS_TOKEN=dummy",
		"SAKURA_ACCESS_TOKEN_SECRET=dummy",
	}); err != nil {
		t.Fatal(err)
	}
	// By default the SDK retries failed calls with a backoff and limits
	// itself to 5 requests per second. The tests look at single calls and
	// want to be fast.
	noRetry, err := sa.DupWith(saclient.WithoutRetry(), saclient.WithoutAPIRequestRateLimit())
	if err != nil {
		t.Fatal(err)
	}
	client, err := kms.NewClient(noRetry)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, api: kms.NewKeyOp(client)}
}

func (e *env) client() sakurakms.Client {
	return countingClient{KeyAPI: e.api, calls: &e.calls}
}

// createKey creates a KMS key and returns its resource ID.
func (e *env) createKey(name string) string {
	e.t.Helper()
	key, err := e.api.Create(e.t.Context(), kms.CreateParams{Name: name})
	if err != nil {
		e.t.Fatalf("create key %s: %v", name, err)
	}
	return key.ID
}

func TestBackend(t *testing.T) {
	e := newEnv(t, mock.Config{})
	ctx := t.Context()
	idA, idB := e.createKey("a"), e.createKey("b")
	b := sakurakms.New(e.client(), sakurakms.WithKeys(map[string]string{"a": idA, "b": idB, "gone": "999999999999"}))

	wk, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "a", Plaintext: []byte("secret"), AAD: []byte("aad")})
	if err != nil {
		t.Fatal(err)
	}
	if wk.KeyRef != idA || wk.Version != 1 || bytes.Contains(wk.Blob, []byte("secret")) {
		t.Errorf("wrapped key = %+v", wk)
	}
	decrypt := func(name string, wk transhim.WrappedKey, aad string) ([]byte, error) {
		return b.Decrypt(ctx, transhim.DecryptRequest{MountID: "m", KeyName: name, Wrapped: wk, AAD: []byte(aad)})
	}
	if got, err := decrypt("a", wk, "aad"); err != nil || string(got) != "secret" {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}

	// the AAD is bound although KMS has no parameter for it
	if _, err := decrypt("a", wk, "other aad"); !errors.Is(err, transhim.ErrCiphertextMismatch) {
		t.Errorf("wrong AAD: err = %v, want ErrCiphertextMismatch", err)
	}
	if _, err := decrypt("a", wk, ""); !errors.Is(err, transhim.ErrCiphertextMismatch) {
		t.Errorf("no AAD: err = %v, want ErrCiphertextMismatch", err)
	}
	// the key is the one the name resolves to
	if _, err := decrypt("b", wk, "aad"); !errors.Is(err, transhim.ErrCiphertextMismatch) {
		t.Errorf("wrong key: err = %v, want ErrCiphertextMismatch", err)
	}
	tampered := wk
	tampered.Blob = bytes.Clone(wk.Blob)
	tampered.Blob[len(tampered.Blob)-1] ^= 1
	if _, err := decrypt("a", tampered, "aad"); !errors.Is(err, transhim.ErrCiphertextMismatch) {
		t.Errorf("tampered: err = %v, want ErrCiphertextMismatch", err)
	}
	for name, bad := range map[string]transhim.WrappedKey{
		"other version": {KeyRef: idA, Version: 2, Blob: wk.Blob},
		"empty blob":    {KeyRef: idA, Version: 1},
		"huge blob":     {KeyRef: idA, Version: 1, Blob: make([]byte, 4096)},
	} {
		before := e.calls.Load()
		if _, err := decrypt("a", bad, "aad"); !errors.Is(err, transhim.ErrCiphertextMismatch) || e.calls.Load() != before {
			t.Errorf("%s: err = %v, KMS calls = %d; want ErrCiphertextMismatch without a call", name, err, e.calls.Load()-before)
		}
	}

	// names outside the map, and keys KMS does not have
	for _, name := range []string{"unlisted", idA, "gone"} {
		if _, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: name, Plaintext: []byte("p")}); !errors.Is(err, transhim.ErrKeyNotFound) {
			t.Errorf("Encrypt with %q: err = %v, want ErrKeyNotFound", name, err)
		}
		if _, err := decrypt(name, wk, "aad"); !errors.Is(err, transhim.ErrKeyNotFound) {
			t.Errorf("Decrypt with %q: err = %v, want ErrKeyNotFound", name, err)
		}
	}

	// sizes: empty, and up to the limit
	for _, size := range []int{0, 1, 64, sakurakms.MaxPlaintextSize} {
		plaintext := bytes.Repeat([]byte{'x'}, size)
		wk, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "a", Plaintext: plaintext, AAD: []byte("aad")})
		if err != nil {
			t.Fatalf("Encrypt of %d bytes: %v", size, err)
		}
		if got, err := decrypt("a", wk, "aad"); err != nil || !bytes.Equal(got, plaintext) {
			t.Errorf("Decrypt of %d bytes: %d bytes, %v", size, len(got), err)
		}
	}
	_, err = b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "a", Plaintext: make([]byte, sakurakms.MaxPlaintextSize+1)})
	if !errors.Is(err, transhim.ErrInvalidRequest) {
		t.Errorf("Encrypt over the limit: err = %v, want ErrInvalidRequest", err)
	}

	// a suspended key is how access is revoked in KMS: nothing decrypts
	if _, err := e.api.ChangeStatus(ctx, idA, v1.ChangeKeyStateRequestStatusSuspended); err != nil {
		t.Fatalf("suspend key: %v", err)
	}
	if got, err := decrypt("a", wk, "aad"); err == nil {
		t.Errorf("Decrypt with a suspended key returned %q", got)
	}
	if _, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "a", Plaintext: []byte("p")}); err == nil {
		t.Error("Encrypt with a suspended key succeeded")
	}
}

// TestPayloadLayout pins what is sent to KMS: it is part of the on-disk
// contract.
func TestPayloadLayout(t *testing.T) {
	c := &recordingClient{}
	b := sakurakms.New(c)
	_, err := b.Encrypt(t.Context(), transhim.EncryptRequest{MountID: "m", KeyName: "123456789012", Plaintext: []byte("plaintext"), AAD: []byte("aad")})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("aad"))
	want := append(append([]byte{0x01}, sum[:]...), "plaintext"...)
	if c.id != "123456789012" || !bytes.Equal(c.plain, want) || c.algo != v1.EncryptionRequestAlgoAes256Gcm {
		t.Errorf("KMS got id %q, algo %q, payload %x; want payload %x", c.id, c.algo, c.plain, want)
	}
}

type recordingClient struct {
	id    string
	plain []byte
	algo  v1.EncryptionRequestAlgo
	err   error
}

func (c *recordingClient) Encrypt(_ context.Context, id string, plain []byte, algo v1.EncryptionRequestAlgo) (string, error) {
	c.id, c.plain, c.algo = id, bytes.Clone(plain), algo
	if c.err != nil {
		return "", c.err
	}
	return base64.StdEncoding.EncodeToString(plain), nil
}

func (c *recordingClient) Decrypt(_ context.Context, id, cipher string) ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	return base64.StdEncoding.DecodeString(cipher)
}

// TestForeignPlaintext: what KMS decrypts must carry the backend's header. A
// ciphertext made with the same KMS key by something else is refused.
func TestForeignPlaintext(t *testing.T) {
	c := &recordingClient{}
	b := sakurakms.New(c)
	for name, payload := range map[string][]byte{
		"empty":         {},
		"short":         []byte("too short"),
		"other version": append([]byte{0x02}, make([]byte, 40)...),
		"raw data key":  make([]byte, 64),
	} {
		_, err := b.Decrypt(t.Context(), transhim.DecryptRequest{
			KeyName: "1", Wrapped: transhim.WrappedKey{Version: 1, Blob: append([]byte{0}, payload...)}, AAD: []byte("aad"),
		})
		_ = payload
		if !errors.Is(err, transhim.ErrCiphertextMismatch) {
			t.Errorf("%s: err = %v, want ErrCiphertextMismatch", name, err)
		}
	}
}

func TestKeyResolution(t *testing.T) {
	ctx := t.Context()
	c := &recordingClient{}
	// by default the key name is the resource ID, and must look like one
	b := sakurakms.New(c)
	if _, err := b.Encrypt(ctx, transhim.EncryptRequest{KeyName: "123456789012", Plaintext: []byte("p")}); err != nil || c.id != "123456789012" {
		t.Errorf("default: id = %q, err = %v", c.id, err)
	}
	for _, name := range []string{"my-key", "12a", "../1", "1/encrypt"} {
		c.id = ""
		if _, err := b.Encrypt(ctx, transhim.EncryptRequest{KeyName: name, Plaintext: []byte("p")}); !errors.Is(err, transhim.ErrKeyNotFound) || c.id != "" {
			t.Errorf("%q: err = %v, KMS called with %q; want ErrKeyNotFound without a call", name, err, c.id)
		}
	}
	b = sakurakms.New(c, sakurakms.WithKeyID(func(mountID, keyName string) (string, bool) {
		return "42", mountID == "m" && keyName == "k"
	}))
	if _, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "m", KeyName: "k", Plaintext: []byte("p")}); err != nil || c.id != "42" {
		t.Errorf("WithKeyID: id = %q, err = %v", c.id, err)
	}
	if _, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: "other", KeyName: "k", Plaintext: []byte("p")}); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("WithKeyID refusing: err = %v, want ErrKeyNotFound", err)
	}
}

func TestErrorMapping(t *testing.T) {
	status := func(code int) error {
		return kms.NewAPIError("Key.Op", code, &ogen.UnexpectedStatusCodeError{StatusCode: code, Payload: &http.Response{StatusCode: code}})
	}
	tests := []struct {
		err         error
		wantEncrypt error
		wantDecrypt error
		retryable   bool
	}{
		{status(404), transhim.ErrKeyNotFound, transhim.ErrKeyNotFound, false},
		{status(400), transhim.ErrInvalidRequest, transhim.ErrCiphertextMismatch, false},
		{status(401), transhim.ErrPermissionDenied, transhim.ErrPermissionDenied, false},
		{status(403), transhim.ErrPermissionDenied, transhim.ErrPermissionDenied, false},
		{status(429), transhim.ErrUpstream, transhim.ErrUpstream, true},
		{status(500), transhim.ErrUpstream, transhim.ErrUpstream, true},
		{status(503), transhim.ErrUpstream, transhim.ErrUpstream, true},
		{status(409), transhim.ErrUpstream, transhim.ErrUpstream, false},
		{kms.NewAPIError("Key.Op", 0, errors.New("dial tcp: connection refused")), transhim.ErrUpstream, transhim.ErrUpstream, true},
	}
	ctx := t.Context()
	for _, tt := range tests {
		b := sakurakms.New(&recordingClient{err: tt.err})
		_, encErr := b.Encrypt(ctx, transhim.EncryptRequest{KeyName: "1", Plaintext: []byte("p")})
		_, decErr := b.Decrypt(ctx, transhim.DecryptRequest{KeyName: "1", Wrapped: transhim.WrappedKey{Version: 1, Blob: []byte("blob")}})
		for op, c := range map[string]struct{ got, want error }{"Encrypt": {encErr, tt.wantEncrypt}, "Decrypt": {decErr, tt.wantDecrypt}} {
			if !errors.Is(c.got, c.want) {
				t.Errorf("%s with %v: err = %v, want %v", op, tt.err, c.got, c.want)
			}
			ue, ok := errors.AsType[*transhim.UpstreamError](c.got)
			if (ok && ue.Retryable) != tt.retryable {
				t.Errorf("%s with %v: retryable = %v, want %v", op, tt.err, ok && ue.Retryable, tt.retryable)
			}
			// the KMS error stays available for logs and audit
			if !errors.Is(c.got, tt.err) {
				t.Errorf("%s with %v: the KMS error is not in the chain of %v", op, tt.err, c.got)
			}
		}
	}

	b := sakurakms.New(&recordingClient{err: fmt.Errorf("kms: %w", context.Canceled)})
	_, err := b.Encrypt(ctx, transhim.EncryptRequest{KeyName: "1", Plaintext: []byte("p")})
	if !errors.Is(err, context.Canceled) || errors.Is(err, transhim.ErrUpstream) {
		t.Errorf("canceled: err = %v, want context.Canceled and not ErrUpstream", err)
	}
}

// TestKMSFailures: what the client sees when KMS itself fails.
func TestKMSFailures(t *testing.T) {
	for fault, want := range map[string]int{"503:1": 503, "429:1": 503, "500:1": 503, "reset:1": 503} {
		t.Run(fault, func(t *testing.T) {
			e := newEnv(t, mock.Config{Fault: []string{fault}})
			_, err := sakurakms.New(e.client()).Encrypt(t.Context(), transhim.EncryptRequest{KeyName: "123456789012", Plaintext: []byte("p")})
			ue, ok := errors.AsType[*transhim.UpstreamError](err)
			if !ok || !ue.Retryable {
				t.Errorf("err = %v, want a retryable UpstreamError (answered with %d)", err, want)
			}
		})
	}
}

func newServer(t *testing.T, e *env, kmsKeys map[string]string, rootID string, cache bool) (*transhim.Server, string) {
	t.Helper()
	const token = "conformance-token"
	sseS3, err := hierarchical.New(sakurakms.New(e.client()), rootID, memstore.New())
	if err != nil {
		t.Fatal(err)
	}
	opts := []transhim.Option{
		transhim.Mount("/v1/transit-kms", "rgw-kms", sakurakms.New(e.client(), sakurakms.WithKeys(kmsKeys)),
			transhim.WithMaxPlaintextSize(sakurakms.MaxPlaintextSize)),
		transhim.Mount("/v1/transit-sse-s3", "rgw-sse-s3", sseS3),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(token)),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
	}
	if cache {
		opts = append(opts, transhim.WithDecryptCache(transhim.DecryptCacheConfig{MaxEntries: 100, TTL: time.Minute, WarmOnDatakey: true}))
	}
	srv, err := transhim.NewServer(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return srv, token
}

// TestConformance runs the conformance suite on the two mounts of the example
// server.
func TestConformance(t *testing.T) {
	e := newEnv(t, mock.Config{})
	keys := map[string]string{"key-a": e.createKey("key-a"), "key-b": e.createKey("key-b")}
	srv, token := newServer(t, e, keys, e.createKey("root"), true)

	t.Run("SSE-KMS mount", func(t *testing.T) {
		transhimtest.RunConformance(t, transhimtest.Conformance{
			Handler: srv, Prefix: "/v1/transit-kms", Token: token,
			KeyNames: [2]string{"key-a", "key-b"}, MaxPlaintextSize: sakurakms.MaxPlaintextSize,
		})
	})
	t.Run("SSE-S3 mount", func(t *testing.T) {
		transhimtest.RunConformance(t, transhimtest.Conformance{
			Handler: srv, Prefix: "/v1/transit-sse-s3", Token: token, ManagedKeys: true,
		})
	})
}

// TestSlowKMS shows what keeps a slow KMS bearable: with the decrypt cache and
// the hierarchical backend, a burst of requests for one bucket costs a single
// KMS call each for the bucket key and nothing per decrypt.
func TestSlowKMS(t *testing.T) {
	const latency = 200 * time.Millisecond
	e := newEnv(t, mock.Config{Latency: latency})
	rootID := e.createKey("root")
	srv, token := newServer(t, e, nil, rootID, true)
	c := &client{t: t, handler: srv, token: token}

	e.calls.Store(0)
	c.do("POST", "/v1/transit-sse-s3/keys/bucket", ``, 204)
	if n := e.calls.Load(); n != 1 {
		t.Fatalf("creating the bucket key made %d KMS calls, want 1", n)
	}

	// 16 objects written at once, then each read 3 times: no further KMS call,
	// since the bucket key is in memory and the data keys are in the cache
	start := time.Now()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			dk := c.do("POST", "/v1/transit-sse-s3/datakey/plaintext/bucket", ``, 200)
			for range 3 {
				d := c.do("POST", "/v1/transit-sse-s3/decrypt/bucket", `{"ciphertext":"`+dk["ciphertext"]+`"}`, 200)
				if d["plaintext"] != dk["plaintext"] {
					t.Error("decrypt returned another plaintext")
				}
			}
		})
	}
	wg.Wait()
	if n := e.calls.Load(); n != 1 {
		t.Errorf("%d KMS calls in total, want 1", n)
	}
	if d := time.Since(start); d > latency {
		t.Errorf("the burst took %v although it needed no KMS call", d)
	}
}
