package transhim_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/transhimtest"
)

const testToken = "test-token"

// env is a server with two mounts on one fake backend.
type env struct {
	t       *testing.T
	backend *transhimtest.FakeBackend
	handler http.Handler
	logs    *bytes.Buffer
}

func newEnv(t *testing.T, opts ...transhim.Option) *env {
	t.Helper()
	e := &env{t: t, backend: transhimtest.NewFakeBackend(), logs: &bytes.Buffer{}}
	e.backend.AddKey("kms", "key1")
	e.backend.AddKey("kms", "key2")
	e.backend.AddKey("sse", "key1")
	logger := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opts = append([]transhim.Option{
		transhim.Mount("/v1/transit-kms", "kms", e.backend),
		transhim.Mount("/v1/transit-sse-s3", "sse", e.backend),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(testToken)),
		transhim.WithLogger(logger),
	}, opts...)
	srv, err := transhim.NewServer(opts...)
	if err != nil {
		t.Fatal(err)
	}
	e.handler = srv
	return e
}

type reply struct {
	status int
	header http.Header
	body   []byte
	// decoded body
	Data     map[string]any `json:"data"`
	Errors   []string       `json:"errors"`
	Warnings []string       `json:"warnings"`
}

func (r *reply) str(field string) string {
	s, _ := r.Data[field].(string)
	return s
}

// do sends a request the way RGW does: no Content-Type, token in X-Vault-Token.
func (e *env) do(method, path, body string) *reply {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Vault-Token", testToken)
	return e.send(req)
}

func (e *env) send(req *http.Request) *reply {
	e.t.Helper()
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	res := w.Result()
	b, _ := io.ReadAll(res.Body)
	r := &reply{status: res.StatusCode, header: res.Header, body: b}
	if res.StatusCode == http.StatusNoContent {
		// RGW needs these answers to be really empty
		if len(b) != 0 || res.Header.Get("Content-Type") != "" || res.Header.Get("Content-Length") != "" {
			e.t.Errorf("%s %s: 204 with body %q, headers %v", req.Method, req.URL, b, res.Header)
		}
		return r
	}
	if err := json.Unmarshal(b, r); err != nil {
		e.t.Fatalf("%s %s: response is not JSON: %q", req.Method, req.URL, b)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		e.t.Errorf("%s %s: Content-Type = %q", req.Method, req.URL, ct)
	}
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		e.t.Errorf("%s %s: Cache-Control = %q", req.Method, req.URL, cc)
	}
	return r
}

// wantError checks a Vault-style error answer.
func (e *env) wantError(r *reply, status int, msg string) {
	e.t.Helper()
	if r.status != status || len(r.Errors) != 1 || r.Errors[0] != msg {
		e.t.Errorf("got %d %q, want %d [%q]", r.status, r.body, status, msg)
	}
	if r.Data != nil {
		e.t.Errorf("error answer carries data: %q", r.body)
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func jsonBody(fields map[string]any) string {
	b, _ := json.Marshal(fields)
	return string(b)
}

// rgwContext is what RGW sends as context.
var rgwContext = b64(`{"aws:s3:arn":"arn:aws:s3::owner:bucket/object"}`)

func TestDataKeyAndDecrypt(t *testing.T) {
	e := newEnv(t)
	for _, tt := range []struct {
		name string
		body string
		size int
	}{
		{"rgw", jsonBody(map[string]any{"context": rgwContext}), 32},
		{"no body", "", 32},
		{"empty object", "{}", 32},
		{"128 bits", `{"bits":128}`, 16},
		{"256 bits", `{"bits":256}`, 32},
		{"512 bits", `{"bits":512}`, 64},
		{"ignored fields", `{"nonce":"abc","unknown":{"a":1}}`, 32},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", tt.body)
			if r.status != http.StatusOK {
				t.Fatalf("datakey: %d %q", r.status, r.body)
			}
			plaintext, err := base64.StdEncoding.DecodeString(r.str("plaintext"))
			if err != nil || len(plaintext) != tt.size {
				t.Errorf("plaintext is %d bytes (%v), want %d", len(plaintext), err, tt.size)
			}
			ciphertext := r.str("ciphertext")
			if !strings.HasPrefix(ciphertext, "vault:v1:") {
				t.Errorf("ciphertext = %q", ciphertext)
			}
			if v, _ := r.Data["key_version"].(float64); v != 1 {
				t.Errorf("key_version = %v", r.Data["key_version"])
			}

			var in map[string]any
			if tt.body != "" {
				json.Unmarshal([]byte(tt.body), &in)
			}
			dec := map[string]any{"ciphertext": ciphertext}
			if c, ok := in["context"]; ok {
				dec["context"] = c
			}
			d := e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", jsonBody(dec))
			if d.status != http.StatusOK || d.str("plaintext") != r.str("plaintext") {
				t.Errorf("decrypt: %d %q, want plaintext %q", d.status, d.body, r.str("plaintext"))
			}
		})
	}
	if n := e.backend.Calls(transhimtest.OpGenerateDataKey); n != 0 {
		t.Errorf("GenerateDataKey called %d times on a backend without it", n)
	}
}

func TestDataKeysDiffer(t *testing.T) {
	e := newEnv(t)
	a := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", "")
	b := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", "")
	if a.str("plaintext") == b.str("plaintext") || a.str("ciphertext") == b.str("ciphertext") {
		t.Error("two datakey calls returned the same key")
	}
}

func TestDataKeyGenerator(t *testing.T) {
	fb := transhimtest.NewFakeBackend()
	fb.AddKey("m", "k")
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/transit", "m", fb.WithDataKeyGenerator()),
		transhim.AllowUnauthenticated(),
	)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, backend: fb, handler: srv}
	r := e.do(http.MethodPost, "/v1/transit/datakey/plaintext/k", `{"bits":512}`)
	if r.status != http.StatusOK {
		t.Fatalf("datakey: %d %q", r.status, r.body)
	}
	if p, _ := base64.StdEncoding.DecodeString(r.str("plaintext")); len(p) != 64 {
		t.Errorf("plaintext is %d bytes, want 64", len(p))
	}
	if g, enc := fb.Calls(transhimtest.OpGenerateDataKey), fb.Calls(transhimtest.OpEncrypt); g != 1 || enc != 0 {
		t.Errorf("GenerateDataKey called %d times, Encrypt %d times; want 1, 0", g, enc)
	}
	d := e.do(http.MethodPost, "/v1/transit/decrypt/k", jsonBody(map[string]any{"ciphertext": r.str("ciphertext")}))
	if d.status != http.StatusOK || d.str("plaintext") != r.str("plaintext") {
		t.Errorf("decrypt: %d %q", d.status, d.body)
	}
}

// shortKeyBackend returns data keys of the wrong length.
type shortKeyBackend struct{ transhim.Backend }

func (shortKeyBackend) GenerateDataKey(context.Context, transhim.DataKeyRequest) ([]byte, transhim.WrappedKey, error) {
	return []byte("short"), transhim.WrappedKey{Blob: []byte("x")}, nil
}

func TestDataKeyGeneratorWrongLength(t *testing.T) {
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/transit", "m", shortKeyBackend{transhimtest.NewFakeBackend()}),
		transhim.AllowUnauthenticated(),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
	)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, handler: srv}
	e.wantError(e.do(http.MethodPost, "/v1/transit/datakey/plaintext/k", ""), 500, "internal error")
}

func TestEncrypt(t *testing.T) {
	e := newEnv(t)
	for _, plaintext := range []string{"hello", "", strings.Repeat("x", transhim.DefaultMaxPlaintextSize)} {
		body := map[string]any{"plaintext": b64(plaintext), "context": b64("ctx")}
		r := e.do(http.MethodPost, "/v1/transit-kms/encrypt/key1", jsonBody(body))
		if r.status != http.StatusOK {
			t.Fatalf("encrypt: %d %q", r.status, r.body)
		}
		if v, _ := r.Data["key_version"].(float64); v != 1 {
			t.Errorf("key_version = %v", r.Data["key_version"])
		}
		if len(r.Warnings) != 0 {
			t.Errorf("warnings = %q", r.Warnings)
		}
		d := e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1",
			jsonBody(map[string]any{"ciphertext": r.str("ciphertext"), "context": b64("ctx")}))
		if d.status != http.StatusOK || d.str("plaintext") != b64(plaintext) {
			t.Errorf("decrypt: %d %q", d.status, d.body)
		}
	}

	t.Run("key_version is ignored with a warning", func(t *testing.T) {
		r := e.do(http.MethodPost, "/v1/transit-kms/encrypt/key1", `{"plaintext":"aGVsbG8=","key_version":3}`)
		if r.status != http.StatusOK || len(r.Warnings) != 1 {
			t.Errorf("got %d %q", r.status, r.body)
		}
	})
	t.Run("too large", func(t *testing.T) {
		body := jsonBody(map[string]any{"plaintext": b64(strings.Repeat("x", transhim.DefaultMaxPlaintextSize+1))})
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/encrypt/key1", body), 400, "plaintext too large")
		body = jsonBody(map[string]any{"plaintext": b64(strings.Repeat("x", 100000))})
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/encrypt/key1", body), 400, "plaintext too large")
	})
	t.Run("missing plaintext", func(t *testing.T) {
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/encrypt/key1", "{}"), 400, "missing plaintext to encrypt")
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/encrypt/key1", ""), 400, "missing plaintext to encrypt")
	})
	t.Run("bad base64", func(t *testing.T) {
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/encrypt/key1", `{"plaintext":"***"}`), 400, "failed to base64-decode plaintext")
	})
	t.Run("no auto-create", func(t *testing.T) {
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/encrypt/nokey", `{"plaintext":"aGVsbG8="}`), 400, "encryption key not found")
	})
}

func TestMaxPlaintextSize(t *testing.T) {
	fb := transhimtest.NewFakeBackend()
	fb.AddKey("m", "k")
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/transit", "m", fb, transhim.WithMaxPlaintextSize(8)),
		transhim.AllowUnauthenticated(),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
	)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, handler: srv}
	if r := e.do(http.MethodPost, "/v1/transit/encrypt/k", jsonBody(map[string]any{"plaintext": b64("12345678")})); r.status != 200 {
		t.Errorf("8 bytes: %d %q", r.status, r.body)
	}
	e.wantError(e.do(http.MethodPost, "/v1/transit/encrypt/k", jsonBody(map[string]any{"plaintext": b64("123456789")})), 400, "plaintext too large")
}

// TestBinding checks that a ciphertext only decrypts with the mount, key name,
// and context it was made for.
func TestBinding(t *testing.T) {
	e := newEnv(t)
	r := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", jsonBody(map[string]any{"context": rgwContext}))
	if r.status != http.StatusOK {
		t.Fatalf("datakey: %d %q", r.status, r.body)
	}
	ct := r.str("ciphertext")
	decrypt := func(path, ciphertext, context string) *reply {
		body := map[string]any{"ciphertext": ciphertext}
		if context != "" {
			body["context"] = context
		}
		return e.do(http.MethodPost, path, jsonBody(body))
	}

	if d := decrypt("/v1/transit-kms/decrypt/key1", ct, rgwContext); d.status != 200 || d.str("plaintext") != r.str("plaintext") {
		t.Fatalf("matching decrypt: %d %q", d.status, d.body)
	}
	t.Run("wrong key name", func(t *testing.T) {
		e.wantError(decrypt("/v1/transit-kms/decrypt/key2", ct, rgwContext), 400, "invalid ciphertext")
	})
	t.Run("wrong mount", func(t *testing.T) {
		e.wantError(decrypt("/v1/transit-sse-s3/decrypt/key1", ct, rgwContext), 400, "invalid ciphertext")
	})
	t.Run("wrong context", func(t *testing.T) {
		e.wantError(decrypt("/v1/transit-kms/decrypt/key1", ct, b64("other")), 400, "invalid ciphertext")
	})
	t.Run("missing context", func(t *testing.T) {
		e.wantError(decrypt("/v1/transit-kms/decrypt/key1", ct, ""), 400, "invalid ciphertext")
	})
	t.Run("context added", func(t *testing.T) {
		plain := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", "")
		e.wantError(decrypt("/v1/transit-kms/decrypt/key1", plain.str("ciphertext"), rgwContext), 400, "invalid ciphertext")
	})
	t.Run("tampered", func(t *testing.T) {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ct, "vault:v1:"))
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-1] ^= 1
		tampered := "vault:v1:" + base64.StdEncoding.EncodeToString(raw)
		e.wantError(decrypt("/v1/transit-kms/decrypt/key1", tampered, rgwContext), 400, "invalid ciphertext")
	})
	t.Run("malformed", func(t *testing.T) {
		for _, bad := range []string{"", "garbage", "vault:v1:!!!", "vault:v1:AAAA", strings.TrimPrefix(ct, "vault:")} {
			e.wantError(decrypt("/v1/transit-kms/decrypt/key1", bad, rgwContext), 400, "invalid ciphertext")
		}
	})
	t.Run("missing key", func(t *testing.T) {
		e.wantError(decrypt("/v1/transit-kms/decrypt/nokey", ct, rgwContext), 400, "encryption key not found")
	})
}

func TestRequestErrors(t *testing.T) {
	e := newEnv(t)
	post := func(path, body string) *reply { return e.do(http.MethodPost, path, body) }

	e.wantError(post("/v1/transit-kms/datakey/plaintext/nokey", ""), 400, "encryption key not found")
	for _, body := range []string{`{"bits":0}`, `{"bits":192}`, `{"bits":1024}`, `{"bits":-256}`} {
		e.wantError(post("/v1/transit-kms/datakey/plaintext/key1", body), 400, "invalid bit length")
	}
	for _, body := range []string{`{`, `[]`, `"x"`, `{"bits":"abc"}`, `{"context":1}`, `{} trailing`} {
		e.wantError(post("/v1/transit-kms/datakey/plaintext/key1", body), 400, "failed to decode JSON input")
	}
	e.wantError(post("/v1/transit-kms/datakey/plaintext/key1", `{"context":"***"}`), 400, "failed to base64-decode context")
	e.wantError(post("/v1/transit-kms/decrypt/key1", `{}`), 400, "missing ciphertext to decrypt")
	e.wantError(post("/v1/transit-kms/decrypt/key1", `{"ciphertext":"vault:v1:AQAAAA==","context":"***"}`), 400, "failed to base64-decode context")
}

func TestRouting(t *testing.T) {
	e := newEnv(t)
	notFound := []string{
		"/",
		"/v1",
		"/v1/transit-kms",
		"/v1/transit-kms/",
		"/v1/transit/datakey/plaintext/key1", // no such mount
		"/v1/transit-kmsx/datakey/plaintext/key1",
		"/v1/transit-kms/datakey/wrapped/key1", // deferred (D3)
		"/v1/transit-kms/datakey/plaintext",
		"/v1/transit-kms/encrypt",
		"/v1/transit-kms/rewrap/key1",
		"/v1/transit-kms/export/encryption-key/key1",
		"/v1/sys/health",
		"/v1/auth/token/lookup-self",
	}
	for _, path := range notFound {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if r := e.do(method, path, ""); r.status != http.StatusNotFound || len(r.Errors) != 1 {
				t.Errorf("%s %s: got %d %q, want 404", method, path, r.status, r.body)
			}
		}
	}
	// unknown paths under a mount are logged, so that API drift is noticed
	if logs := e.logs.String(); !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "/v1/transit-kms/rewrap/key1") {
		t.Errorf("unsupported path was not logged at WARN:\n%s", logs)
	}

	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodHead, http.MethodPatch} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/v1/transit-kms/datakey/plaintext/key1", nil)
		req.Header.Set("X-Vault-Token", testToken)
		e.handler.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") == "" {
			t.Errorf("%s: got %d, Allow %q", method, w.Code, w.Header().Get("Allow"))
		}
	}
	if r := e.do(http.MethodPut, "/v1/transit-kms/datakey/plaintext/key1", ""); r.status != http.StatusOK {
		t.Errorf("PUT: %d %q", r.status, r.body)
	}
}

func TestNestedPrefixes(t *testing.T) {
	fb := transhimtest.NewFakeBackend()
	fb.AddKey("inner", "k")
	fb.AddKey("outer", "k")
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/transit", "outer", fb),
		transhim.Mount("v1/transit/datakey/", "inner", fb),
		transhim.AllowUnauthenticated(),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
	)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, handler: srv}
	// the longest prefix wins, so this is "encrypt" on the inner mount
	r := e.do(http.MethodPost, "/v1/transit/datakey/encrypt/k", `{"plaintext":"aGVsbG8="}`)
	if r.status != http.StatusOK {
		t.Fatalf("inner encrypt: %d %q", r.status, r.body)
	}
	body := jsonBody(map[string]any{"ciphertext": r.str("ciphertext")})
	if d := e.do(http.MethodPost, "/v1/transit/datakey/decrypt/k", body); d.status != http.StatusOK {
		t.Errorf("inner decrypt: %d %q", d.status, d.body)
	}
	e.wantError(e.do(http.MethodPost, "/v1/transit/decrypt/k", body), 400, "invalid ciphertext")
}

func TestKeyNames(t *testing.T) {
	e := newEnv(t)
	names := map[string]string{ // escaped path segment -> key name
		"tenant$user":            "tenant$user",
		"tenant%24user":          "tenant$user",
		"a.b_c-d":                "a.b_c-d",
		"1434f035-2747.4126.2":   "1434f035-2747.4126.2",
		"with%20space":           "with space",
		"plus+sign":              "plus+sign",
		"%E6%97%A5%E6%9C%AC":     "日本",
		"percent%2525":           "percent%25", // unescaped exactly once
		"arn:aws:kms:region:key": "arn:aws:kms:region:key",
	}
	for escaped, name := range names {
		e.backend.AddKey("kms", name)
		r := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/"+escaped, "")
		if r.status != http.StatusOK {
			t.Errorf("%s: %d %q", escaped, r.status, r.body)
		}
	}
	for _, escaped := range []string{"", "a/b", "a%2Fb", "a/", "a%00b", "a%0Ab", "a%7Fb", "a%FFb"} {
		r := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/"+escaped, "")
		if r.status != http.StatusBadRequest || len(r.Errors) != 1 || !strings.HasPrefix(r.Errors[0], "invalid key name") {
			t.Errorf("%q: got %d %q, want 400 invalid key name", escaped, r.status, r.body)
		}
	}
	if n := e.backend.Calls(transhimtest.OpEncrypt); n != len(names) {
		t.Errorf("backend called %d times, want %d", n, len(names))
	}
}

func TestStaticTokenAuthorizer(t *testing.T) {
	e := newEnv(t)
	send := func(tokens ...string) *reply {
		req := httptest.NewRequest(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", nil)
		for _, tok := range tokens {
			req.Header.Add("X-Vault-Token", tok)
		}
		return e.send(req)
	}
	e.wantError(send(), 403, "permission denied")
	e.wantError(send(""), 403, "permission denied")
	e.wantError(send("wrong"), 403, "permission denied")
	e.wantError(send(testToken+"x"), 403, "permission denied")
	e.wantError(send("wrong", testToken), 403, "permission denied") // only the first value counts
	if r := send(testToken); r.status != http.StatusOK {
		t.Errorf("valid token: %d %q", r.status, r.body)
	}
	// RGW sends the header twice
	if r := send(testToken, testToken); r.status != http.StatusOK {
		t.Errorf("duplicated token: %d %q", r.status, r.body)
	}
	if n := e.backend.Calls(transhimtest.OpEncrypt); n != 2 {
		t.Errorf("backend called %d times, want 2: denied requests must not reach it", n)
	}

	deny := transhim.StaticTokenAuthorizer("")
	if err := deny(t.Context(), transhim.AuthRequest{}); !errors.Is(err, transhim.ErrPermissionDenied) {
		t.Errorf("empty configured token: err = %v, want ErrPermissionDenied", err)
	}
}

func TestAuthorizer(t *testing.T) {
	var mu sync.Mutex
	var got []transhim.AuthRequest
	var authErr error
	e := newEnv(t, transhim.WithAuthorizer(func(_ context.Context, req transhim.AuthRequest) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, req)
		return authErr
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", nil)
	req.Header.Set("X-Vault-Token", "tok")
	req.Header.Set("X-Vault-Namespace", "ns1")
	req.RemoteAddr = "192.0.2.1:1234"
	if r := e.send(req); r.status != http.StatusOK {
		t.Fatalf("datakey: %d %q", r.status, r.body)
	}
	e.do(http.MethodPost, "/v1/transit-sse-s3/encrypt/key1", `{"plaintext":""}`)
	e.do(http.MethodPost, "/v1/transit-sse-s3/decrypt/tenant%24user", `{}`)
	// the context reaches the authorizer decoded, for the operations that have one
	const s3Context = `{"aws:s3:arn":"arn:aws:s3::owner:bucket/object"}`
	dk := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", jsonBody(map[string]any{"context": rgwContext}))
	e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", jsonBody(map[string]any{"context": rgwContext, "ciphertext": dk.str("ciphertext")}))
	e.do(http.MethodPost, "/v1/transit-kms/encrypt/key1", jsonBody(map[string]any{"context": rgwContext, "plaintext": ""}))
	e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", `{"context":""}`)
	// a key operation has no context, whatever its body says
	e.do(http.MethodPost, "/v1/transit-sse-s3/keys/b1", jsonBody(map[string]any{"context": rgwContext}))
	// a body that cannot be used is reported after the authorizer had its say
	e.wantError(e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", `{"context":"***"}`), 400, "failed to base64-decode context")
	e.wantError(e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", `{`), 400, "failed to decode JSON input")

	const addr = "192.0.2.1:1234"
	want := []transhim.AuthRequest{
		{Op: transhim.OpDataKey, MountID: "kms", KeyName: "key1", Token: "tok", Namespace: "ns1", RemoteAddr: addr},
		{Op: transhim.OpEncrypt, MountID: "sse", KeyName: "key1", Token: testToken, RemoteAddr: addr},
		{Op: transhim.OpDecrypt, MountID: "sse", KeyName: "tenant$user", Token: testToken, RemoteAddr: addr},
		{Op: transhim.OpDataKey, MountID: "kms", KeyName: "key1", Context: []byte(s3Context), Token: testToken, RemoteAddr: addr},
		{Op: transhim.OpDecrypt, MountID: "kms", KeyName: "key1", Context: []byte(s3Context), Token: testToken, RemoteAddr: addr},
		{Op: transhim.OpEncrypt, MountID: "kms", KeyName: "key1", Context: []byte(s3Context), Token: testToken, RemoteAddr: addr},
		{Op: transhim.OpDataKey, MountID: "kms", KeyName: "key1", Token: testToken, RemoteAddr: addr},
		{Op: transhim.OpKeyCreate, MountID: "sse", KeyName: "b1", Token: testToken, RemoteAddr: addr},
		{Op: transhim.OpDataKey, MountID: "kms", KeyName: "key1", Token: testToken, RemoteAddr: addr},
		{Op: transhim.OpDataKey, MountID: "kms", KeyName: "key1", Token: testToken, RemoteAddr: addr},
	}
	if len(got) != len(want) {
		t.Fatalf("authorizer called %d times, want %d", len(got), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("auth request %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// the authorizer's error decides the answer, and no detail leaks
	for _, tt := range []struct {
		err    error
		status int
		msg    string
	}{
		{errors.Join(transhim.ErrPermissionDenied, errors.New("secret reason")), 403, "permission denied"},
		{&transhim.UpstreamError{Err: errors.New("secret reason"), Retryable: true}, 503, "upstream key service error"},
		{errors.New("secret reason"), 500, "internal error"},
	} {
		authErr = tt.err
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", ""), tt.status, tt.msg)
	}
	if n := e.backend.Calls(transhimtest.OpEncrypt); n != 5 {
		t.Errorf("backend called %d times, want 5", n)
	}
}

// What the authorizer does to the context it was given does not change what is
// bound into the ciphertext.
func TestAuthorizerCannotChangeContext(t *testing.T) {
	e := newEnv(t, transhim.WithAuthorizer(func(_ context.Context, req transhim.AuthRequest) error {
		for i := range req.Context {
			req.Context[i] = 'x'
		}
		return nil
	}))
	dk := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", jsonBody(map[string]any{"context": rgwContext}))
	if dk.status != http.StatusOK {
		t.Fatalf("datakey: %d %q", dk.status, dk.body)
	}
	r := e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", jsonBody(map[string]any{"context": rgwContext, "ciphertext": dk.str("ciphertext")}))
	if r.status != http.StatusOK || r.str("plaintext") != dk.str("plaintext") {
		t.Errorf("decrypt: %d %q", r.status, r.body)
	}
	other := b64(strings.Repeat("x", len(`{"aws:s3:arn":"arn:aws:s3::owner:bucket/object"}`)))
	e.wantError(e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", jsonBody(map[string]any{"context": other, "ciphertext": dk.str("ciphertext")})), 400, "invalid ciphertext")
}

// A client that is not let in learns nothing about its body: not that it was
// too large, and not that it was malformed.
func TestUnauthorizedBody(t *testing.T) {
	e := newEnv(t, transhim.WithMaxBodySize(64))
	for _, body := range []string{`{`, `{"context":"***"}`, `{"context":"` + strings.Repeat("A", 64) + `"}`} {
		req := httptest.NewRequest(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", strings.NewReader(body))
		e.wantError(e.send(req), 403, "permission denied")
	}
}

func TestBackendErrors(t *testing.T) {
	e := newEnv(t)
	r := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", "")
	decryptBody := jsonBody(map[string]any{"ciphertext": r.str("ciphertext")})

	for _, tt := range []struct {
		err    error
		status int
		msg    string
	}{
		{transhim.ErrUpstream, 502, "upstream key service error"},
		{&transhim.UpstreamError{Err: errors.New("SECRET throttled"), Retryable: true}, 503, "upstream key service error"},
		{transhim.ErrPermissionDenied, 403, "permission denied"},
		{errors.Join(transhim.ErrInvalidRequest, errors.New("SECRET detail")), 400, "invalid request"},
		{errors.New("SECRET boom"), 500, "internal error"},
	} {
		e.backend.SetError(transhimtest.OpEncrypt, tt.err)
		e.backend.SetError(transhimtest.OpDecrypt, tt.err)
		for path, body := range map[string]string{
			"/v1/transit-kms/datakey/plaintext/key1": "",
			"/v1/transit-kms/encrypt/key1":           `{"plaintext":"aGVsbG8="}`,
			"/v1/transit-kms/decrypt/key1":           decryptBody,
		} {
			got := e.do(http.MethodPost, path, body)
			e.wantError(got, tt.status, tt.msg)
			if bytes.Contains(got.body, []byte("SECRET")) {
				t.Errorf("%s: error detail leaked: %q", path, got.body)
			}
		}
	}
	// details are in the log instead
	if !strings.Contains(e.logs.String(), "SECRET boom") {
		t.Error("backend error detail is missing from the log")
	}
}

// TestNoSecretsInLogs checks that neither key material nor tokens are logged,
// even at debug level and on failures.
func TestNoSecretsInLogs(t *testing.T) {
	e := newEnv(t)
	r := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", jsonBody(map[string]any{"context": rgwContext}))
	ct := r.str("ciphertext")
	e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", jsonBody(map[string]any{"ciphertext": ct, "context": rgwContext}))
	e.do(http.MethodPost, "/v1/transit-kms/decrypt/key2", jsonBody(map[string]any{"ciphertext": ct, "context": rgwContext}))
	e.do(http.MethodPost, "/v1/transit-kms/encrypt/nokey", jsonBody(map[string]any{"plaintext": b64("SECRET plaintext")}))
	e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", `{"ciphertext": "SECRET`)

	logs := e.logs.String()
	if logs == "" {
		t.Fatal("nothing was logged")
	}
	for _, secret := range []string{r.str("plaintext"), ct, testToken, rgwContext, "SECRET", b64("SECRET plaintext")} {
		if strings.Contains(logs, secret) {
			t.Errorf("%q found in logs:\n%s", secret, logs)
		}
	}
}

func TestMaxBodySize(t *testing.T) {
	e := newEnv(t, transhim.WithMaxBodySize(64))
	fits := `{"context":"` + b64("0123456789012345678901234567890") + `"}`
	if r := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", fits); r.status != http.StatusOK {
		t.Errorf("%d byte body: %d %q", len(fits), r.status, r.body)
	}
	big := `{"context":"` + strings.Repeat("A", 64) + `"}`
	e.wantError(e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", big), 413, "request body too large")
}

func TestResponseShape(t *testing.T) {
	e := newEnv(t)
	r := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", "")
	var top map[string]json.RawMessage
	if err := json.Unmarshal(r.body, &top); err != nil {
		t.Fatal(err)
	}
	// the same top-level fields as Vault
	want := map[string]string{
		"lease_id":       `""`,
		"renewable":      `false`,
		"lease_duration": `0`,
		"wrap_info":      `null`,
		"warnings":       `null`,
		"auth":           `null`,
	}
	for k, v := range want {
		if got := string(top[k]); got != v {
			t.Errorf("%s = %s, want %s", k, got, v)
		}
	}
	if len(top) != len(want)+2 {
		t.Errorf("top-level fields: %q", r.body)
	}
	var id string
	json.Unmarshal(top["request_id"], &id)
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(id) {
		t.Errorf("request_id = %q, want a UUID", id)
	}
	other := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", "")
	if bytes.Equal(top["request_id"], mustRaw(t, other.body, "request_id")) {
		t.Error("request_id repeats")
	}
}

func mustRaw(t *testing.T, body []byte, field string) json.RawMessage {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	return top[field]
}

func TestNewServerErrors(t *testing.T) {
	fb := transhimtest.NewFakeBackend()
	auth := transhim.WithAuthorizer(transhim.StaticTokenAuthorizer("t"))
	tests := map[string][]transhim.Option{
		"no options":            nil,
		"no mount":              {auth},
		"no authorizer":         {transhim.Mount("/v1/transit", "m", fb)},
		"both auth modes":       {transhim.Mount("/v1/transit", "m", fb), auth, transhim.AllowUnauthenticated()},
		"nil authorizer":        {transhim.Mount("/v1/transit", "m", fb), transhim.WithAuthorizer(nil)},
		"nil logger":            {transhim.Mount("/v1/transit", "m", fb), auth, transhim.WithLogger(nil)},
		"zero body size":        {transhim.Mount("/v1/transit", "m", fb), auth, transhim.WithMaxBodySize(0)},
		"empty mount ID":        {transhim.Mount("/v1/transit", "", fb), auth},
		"NUL in mount ID":       {transhim.Mount("/v1/transit", "a\x00b", fb), auth},
		"control in mount ID":   {transhim.Mount("/v1/transit", "a\nb", fb), auth},
		"nil backend":           {transhim.Mount("/v1/transit", "m", nil), auth},
		"empty prefix":          {transhim.Mount("", "m", fb), auth},
		"root prefix":           {transhim.Mount("/", "m", fb), auth},
		"prefix needs escaping": {transhim.Mount("/v1/tran sit", "m", fb), auth},
		"duplicate mount ID":    {transhim.Mount("/v1/a", "m", fb), transhim.Mount("/v1/b", "m", fb), auth},
		"duplicate prefix":      {transhim.Mount("/v1/a", "m1", fb), transhim.Mount("v1/a/", "m2", fb), auth},
		"zero plaintext size":   {transhim.Mount("/v1/a", "m", fb, transhim.WithMaxPlaintextSize(0)), auth},
	}
	for name, opts := range tests {
		if srv, err := transhim.NewServer(opts...); err == nil || srv != nil {
			t.Errorf("%s: NewServer succeeded", name)
		}
	}
	if _, err := transhim.NewServer(transhim.Mount("/v1/a", "m1", fb), transhim.Mount("/v1/b", "m2", fb), auth); err != nil {
		t.Errorf("valid options: %v", err)
	}
	if _, err := transhim.NewServer(transhim.Mount("/v1/a", "m", fb), transhim.AllowUnauthenticated()); err != nil {
		t.Errorf("AllowUnauthenticated: %v", err)
	}
}

// TestOverHTTP runs the RGW request shape through a real HTTP server.
func TestOverHTTP(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewServer(e.handler)
	defer ts.Close()

	post := func(path, body string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Add("X-Vault-Token", testToken)
		req.Header.Add("X-Vault-Token", testToken)
		req.Header.Set("Accept", "*/*")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out struct {
			Data map[string]any `json:"data"`
		}
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, out.Data
	}
	status, dk := post("/v1/transit-sse-s3/datakey/plaintext/key1", jsonBody(map[string]any{"context": rgwContext}))
	if status != http.StatusOK {
		t.Fatalf("datakey: %d", status)
	}
	status, dec := post("/v1/transit-sse-s3/decrypt/key1", jsonBody(map[string]any{"context": rgwContext, "ciphertext": dk["ciphertext"]}))
	if status != http.StatusOK || dec["plaintext"] != dk["plaintext"] {
		t.Errorf("decrypt: %d %v", status, dec)
	}
}

func TestConcurrentRequests(t *testing.T) {
	e := newEnv(t)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 20 {
				r := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", "")
				d := e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", jsonBody(map[string]any{"ciphertext": r.str("ciphertext")}))
				if d.status != http.StatusOK || d.str("plaintext") != r.str("plaintext") {
					t.Errorf("decrypt: %d %q", d.status, d.body)
				}
			}
		})
	}
	wg.Wait()
}
