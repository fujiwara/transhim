package transhimtest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/fujiwara/transhim"
)

// Conformance describes the mount RunConformance tests.
type Conformance struct {
	// Handler is the server under test, usually a *transhim.Server.
	Handler http.Handler
	// Prefix is the prefix of the mount to test, for example "/v1/transit".
	Prefix string
	// Token is sent as X-Vault-Token and must be allowed every operation on
	// the key names below. If it is empty, the server is expected to work
	// without a token, and the check that it rejects requests without one is
	// skipped.
	Token string
	// KeyNames are two key names the suite may use. The defaults are
	// "transhimtest-conformance-1" and "-2".
	KeyNames [2]string
	// ManagedKeys says that the mount's backend implements
	// transhim.KeyLifecycle. The suite then creates the keys itself, and
	// deletes them at the end to check that deleting a key makes its
	// ciphertexts undecryptable at once (also with a decrypt cache).
	// Otherwise both keys must exist before the suite runs.
	ManagedKeys bool
	// MaxPlaintextSize is the mount's limit for encrypt. The default is
	// transhim.DefaultMaxPlaintextSize.
	MaxPlaintextSize int
}

// RunConformance drives every endpoint of a mount, the way clients (Ceph RGW
// in particular) do, including the requests that must be rejected. Use it to
// check a server built on your own Backend:
//
//	srv, _ := transhim.NewServer(transhim.Mount("/v1/transit", "id", myBackend), ...)
//	transhimtest.RunConformance(t, transhimtest.Conformance{
//		Handler: srv, Prefix: "/v1/transit", Token: token,
//	})
//
// It leaves data keys behind in nothing but memory, but it does call the
// backend: with a real KMS it needs the two keys to exist, and it creates and
// deletes them if ManagedKeys is set.
func RunConformance(t *testing.T, c Conformance) {
	t.Helper()
	if c.KeyNames[0] == "" {
		c.KeyNames[0] = "transhimtest-conformance-1"
	}
	if c.KeyNames[1] == "" {
		c.KeyNames[1] = "transhimtest-conformance-2"
	}
	if c.MaxPlaintextSize == 0 {
		c.MaxPlaintextSize = transhim.DefaultMaxPlaintextSize
	}
	c.Prefix = "/" + strings.Trim(c.Prefix, "/")
	s := &suite{c: c}
	key1, key2 := c.KeyNames[0], c.KeyNames[1]

	if c.ManagedKeys {
		t.Run("create keys", func(t *testing.T) {
			// the body Ceph RGW sends
			s.want204(t, s.post(t, "keys/"+key1, `{"type":"chacha20-poly1305","derived":true}`))
			s.want204(t, s.post(t, "keys/"+key2, ``))
		})
	}

	t.Run("datakey", func(t *testing.T) {
		for _, tt := range []struct {
			body string
			size int
		}{
			{``, 32}, {`{}`, 32}, {`{"bits":128}`, 16}, {`{"bits":256}`, 32}, {`{"bits":512}`, 64},
			{`{"context":"` + b64("some context") + `"}`, 32},
			{`{"context":"","nonce":"ignored","unknown":[1]}`, 32},
		} {
			r := s.post(t, "datakey/plaintext/"+key1, tt.body)
			if !s.wantOK(t, r) {
				continue
			}
			s.checkEnvelope(t, r)
			plaintext, err := base64.StdEncoding.DecodeString(r.str("plaintext"))
			if err != nil || len(plaintext) != tt.size {
				t.Errorf("datakey %s: plaintext is %d bytes (%v), want %d", tt.body, len(plaintext), err, tt.size)
			}
			if !strings.HasPrefix(r.str("ciphertext"), "vault:v") {
				t.Errorf("datakey %s: ciphertext = %q, want a vault:vN: prefix", tt.body, r.str("ciphertext"))
			}
			if v, ok := r.Data["key_version"].(float64); !ok || v < 1 {
				t.Errorf("datakey %s: key_version = %v", tt.body, r.Data["key_version"])
			}
			var in struct {
				Context string `json:"context"`
			}
			json.Unmarshal([]byte(tt.body), &in)
			d := s.post(t, "decrypt/"+key1, jsonBody(map[string]any{"ciphertext": r.str("ciphertext"), "context": in.Context}))
			if s.wantOK(t, d) && d.str("plaintext") != r.str("plaintext") {
				t.Errorf("datakey %s: decrypt returned another plaintext", tt.body)
			}
		}
		a, b := s.post(t, "datakey/plaintext/"+key1, ``), s.post(t, "datakey/plaintext/"+key1, ``)
		if a.str("plaintext") == b.str("plaintext") || a.str("ciphertext") == b.str("ciphertext") {
			t.Error("two datakey calls returned the same key")
		}
		for _, body := range []string{`{"bits":0}`, `{"bits":192}`, `{"bits":1024}`} {
			s.wantError(t, s.post(t, "datakey/plaintext/"+key1, body), 400, "invalid bit length")
		}
	})

	t.Run("encrypt", func(t *testing.T) {
		for _, plaintext := range []string{"hello", "", strings.Repeat("x", c.MaxPlaintextSize)} {
			body := jsonBody(map[string]any{"plaintext": b64(plaintext), "context": b64("ctx")})
			r := s.post(t, "encrypt/"+key1, body)
			if !s.wantOK(t, r) {
				continue
			}
			s.checkEnvelope(t, r)
			d := s.post(t, "decrypt/"+key1, jsonBody(map[string]any{"ciphertext": r.str("ciphertext"), "context": b64("ctx")}))
			if s.wantOK(t, d) && d.str("plaintext") != b64(plaintext) {
				t.Errorf("encrypt of %d bytes: decrypt returned another plaintext", len(plaintext))
			}
		}
		tooLarge := jsonBody(map[string]any{"plaintext": b64(strings.Repeat("x", c.MaxPlaintextSize+1))})
		s.wantError(t, s.post(t, "encrypt/"+key1, tooLarge), 400, "plaintext too large")
		s.wantError(t, s.post(t, "encrypt/"+key1, `{}`), 400, "missing plaintext to encrypt")
		s.wantStatus(t, s.post(t, "encrypt/"+key1, `{"plaintext":"!!!"}`), 400)
	})

	t.Run("binding", func(t *testing.T) {
		ctx := b64(`{"aws:s3:arn":"arn:aws:s3::owner:bucket/object"}`)
		r := s.post(t, "datakey/plaintext/"+key1, jsonBody(map[string]any{"context": ctx}))
		if !s.wantOK(t, r) {
			return
		}
		ct := r.str("ciphertext")
		decrypt := func(key, ciphertext, context string) *reply {
			return s.post(t, "decrypt/"+key, jsonBody(map[string]any{"ciphertext": ciphertext, "context": context}))
		}
		if d := decrypt(key1, ct, ctx); s.wantOK(t, d) && d.str("plaintext") != r.str("plaintext") {
			t.Error("decrypt returned another plaintext")
		}
		const invalid = "invalid ciphertext"
		s.wantError(t, decrypt(key2, ct, ctx), 400, invalid)          // wrong key name
		s.wantError(t, decrypt(key1, ct, b64("other")), 400, invalid) // wrong context
		s.wantError(t, decrypt(key1, ct, ""), 400, invalid)           // context dropped
		plain := s.post(t, "datakey/plaintext/"+key1, ``)
		s.wantError(t, decrypt(key1, plain.str("ciphertext"), ctx), 400, invalid) // context added

		i := strings.LastIndex(ct, ":") + 1
		raw, err := base64.StdEncoding.DecodeString(ct[i:])
		if err != nil {
			t.Fatalf("ciphertext payload is not base64: %q", ct)
		}
		raw[len(raw)-1] ^= 1
		s.wantError(t, decrypt(key1, ct[:i]+base64.StdEncoding.EncodeToString(raw), ctx), 400, invalid) // tampered
		for _, malformed := range []string{"", "garbage", "vault:v1:!!!", ct[i:], "vault:v0:" + ct[i:]} {
			s.wantError(t, decrypt(key1, malformed, ctx), 400, invalid)
		}
		s.wantError(t, s.post(t, "decrypt/"+key1, `{}`), 400, "missing ciphertext to decrypt")
	})

	t.Run("missing key", func(t *testing.T) {
		missing := key1 + "-missing"
		const notFound = "encryption key not found"
		s.wantError(t, s.post(t, "datakey/plaintext/"+missing, ``), 400, notFound)
		s.wantError(t, s.post(t, "encrypt/"+missing, `{"plaintext":"aGVsbG8="}`), 400, notFound) // no auto-create
		r := s.post(t, "datakey/plaintext/"+key1, ``)
		s.wantError(t, s.post(t, "decrypt/"+missing, jsonBody(map[string]any{"ciphertext": r.str("ciphertext")})), 400, notFound)
	})

	t.Run("requests", func(t *testing.T) {
		for _, body := range []string{`{`, `[]`, `{"context":1}`} {
			s.wantError(t, s.post(t, "datakey/plaintext/"+key1, body), 400, "failed to decode JSON input")
		}
		s.wantError(t, s.post(t, "datakey/plaintext/"+key1, `{"context":"!!!"}`), 400, "failed to base64-decode context")
		if r := s.do(t, http.MethodPut, "datakey/plaintext/"+key1, ``, s.c.Token); r.status != http.StatusOK {
			t.Errorf("PUT datakey: got %d, want 200", r.status)
		}
		s.wantStatus(t, s.do(t, http.MethodGet, "datakey/plaintext/"+key1, ``, s.c.Token), 405)
		s.wantStatus(t, s.post(t, "rewrap/"+key1, ``), 404)
		s.wantStatus(t, s.post(t, "export/encryption-key/"+key1, ``), 404)
		s.wantStatus(t, s.do(t, http.MethodGet, "keys/"+key1, ``, s.c.Token), 404)
		s.wantStatus(t, s.post(t, "datakey/plaintext/a%2Fb", ``), 400)
		s.wantStatus(t, s.post(t, "datakey/plaintext/", ``), 400)
	})

	if c.Token != "" {
		t.Run("authorization", func(t *testing.T) {
			const denied = "permission denied"
			s.wantError(t, s.do(t, http.MethodPost, "datakey/plaintext/"+key1, ``, ""), 403, denied)
			s.wantError(t, s.do(t, http.MethodPost, "datakey/plaintext/"+key1, ``, c.Token+"x"), 403, denied)
			s.wantError(t, s.do(t, http.MethodPost, "encrypt/"+key1, `{"plaintext":""}`, ""), 403, denied)
			s.wantError(t, s.do(t, http.MethodPost, "decrypt/"+key1, `{}`, ""), 403, denied)
			s.wantError(t, s.do(t, http.MethodPost, "keys/"+key1, ``, ""), 403, denied)
			s.wantError(t, s.do(t, http.MethodPost, "keys/"+key1+"/config", `{"deletion_allowed":true}`, ""), 403, denied)
			s.wantError(t, s.do(t, http.MethodDelete, "keys/"+key1, ``, ""), 403, denied)
			// the key must have survived the rejected delete
			s.wantOK(t, s.post(t, "datakey/plaintext/"+key1, ``))
		})
	}

	t.Run("key operations", func(t *testing.T) {
		s.wantError(t, s.post(t, "keys/"+key1+"-exportable", `{"exportable":true}`), 400, "exportable keys are not supported")
		if !c.ManagedKeys {
			// accepted and ignored, or refused (RejectUnmanagedKeyOps)
			for _, r := range []*reply{
				s.post(t, "keys/"+key1, ``),
				s.post(t, "keys/"+key1+"/config", `{"deletion_allowed":true}`),
				s.do(t, http.MethodDelete, "keys/"+key1, ``, s.c.Token),
			} {
				if r.status != http.StatusMethodNotAllowed {
					s.want204(t, r)
				}
			}
			s.wantOK(t, s.post(t, "datakey/plaintext/"+key1, ``))
			return
		}

		dk := s.post(t, "datakey/plaintext/"+key1, ``)
		if !s.wantOK(t, dk) {
			return
		}
		body := jsonBody(map[string]any{"ciphertext": dk.str("ciphertext")})
		// creating an existing key keeps it: RGW does that, and needs the
		// objects written before to stay readable
		s.want204(t, s.post(t, "keys/"+key1, `{"type":"chacha20-poly1305","derived":true}`))
		// twice, so that the second one is a cache hit if there is a cache
		for range 2 {
			if d := s.post(t, "decrypt/"+key1, body); s.wantOK(t, d) && d.str("plaintext") != dk.str("plaintext") {
				t.Error("decrypt after creating the key again returned another plaintext")
			}
		}

		// what RGW does when a bucket is deleted. The answers must have no
		// body: RGW before tentacle skips the DELETE otherwise.
		s.want204(t, s.post(t, "keys/"+key1+"/config", `{"deletion_allowed":true}`))
		s.want204(t, s.do(t, http.MethodDelete, "keys/"+key1, ``, s.c.Token))
		s.wantError(t, s.post(t, "decrypt/"+key1, body), 400, "encryption key not found")
		s.wantError(t, s.post(t, "datakey/plaintext/"+key1, ``), 400, "encryption key not found")
		// both are idempotent
		s.want204(t, s.do(t, http.MethodDelete, "keys/"+key1, ``, s.c.Token))
		s.want204(t, s.post(t, "keys/"+key1+"/config", `{"deletion_allowed":true}`))

		// a new key under the old name does not bring old data back
		s.want204(t, s.post(t, "keys/"+key1, ``))
		s.wantError(t, s.post(t, "decrypt/"+key1, body), 400, "invalid ciphertext")

		// the other key was not affected; clean up
		s.wantOK(t, s.post(t, "datakey/plaintext/"+key2, ``))
		s.post(t, "keys/"+key1+"/config", `{"deletion_allowed":true}`)
		s.post(t, "keys/"+key2+"/config", `{"deletion_allowed":true}`)
		s.want204(t, s.do(t, http.MethodDelete, "keys/"+key1, ``, s.c.Token))
		s.want204(t, s.do(t, http.MethodDelete, "keys/"+key2, ``, s.c.Token))
	})
}

type suite struct {
	c Conformance
}

type reply struct {
	method, path string
	status       int
	header       http.Header
	body         []byte
	Data         map[string]any `json:"data"`
	Errors       []string       `json:"errors"`
}

func (r *reply) str(field string) string {
	s, _ := r.Data[field].(string)
	return s
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func jsonBody(fields map[string]any) string {
	b, _ := json.Marshal(fields)
	return string(b)
}

func (s *suite) post(t *testing.T, path, body string) *reply {
	t.Helper()
	return s.do(t, http.MethodPost, path, body, s.c.Token)
}

// do sends a request the way Ceph RGW does: no Content-Type, and the token
// twice in X-Vault-Token.
func (s *suite) do(t *testing.T, method, path, body, token string) *reply {
	t.Helper()
	target := s.c.Prefix + "/" + path
	if _, err := url.ParseRequestURI(target); err != nil {
		t.Fatalf("bad test path %q: %v", target, err)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
	if token != "" {
		req.Header.Add("X-Vault-Token", token)
		req.Header.Add("X-Vault-Token", token)
	}
	req.Header.Set("Accept", "*/*")
	w := httptest.NewRecorder()
	s.c.Handler.ServeHTTP(w, req)
	res := w.Result()
	b, _ := io.ReadAll(res.Body)
	r := &reply{method: method, path: path, status: res.StatusCode, header: res.Header, body: b}
	if len(b) > 0 {
		if err := json.Unmarshal(b, r); err != nil {
			t.Errorf("%s %s: response is not JSON: %q", method, path, b)
		}
		if ct := res.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s %s: Content-Type = %q, want application/json", method, path, ct)
		}
	}
	return r
}

func (s *suite) wantStatus(t *testing.T, r *reply, status int) bool {
	t.Helper()
	if r.status != status {
		t.Errorf("%s %s: got %d %q, want %d", r.method, r.path, r.status, r.body, status)
		return false
	}
	return true
}

func (s *suite) wantOK(t *testing.T, r *reply) bool {
	t.Helper()
	return s.wantStatus(t, r, http.StatusOK)
}

func (s *suite) want204(t *testing.T, r *reply) {
	t.Helper()
	if s.wantStatus(t, r, http.StatusNoContent) && len(r.body) != 0 {
		t.Errorf("%s %s: 204 with a body: %q", r.method, r.path, r.body)
	}
}

func (s *suite) wantError(t *testing.T, r *reply, status int, msg string) {
	t.Helper()
	if r.status != status || len(r.Errors) != 1 || r.Errors[0] != msg {
		t.Errorf("%s %s: got %d %q, want %d with the error %q", r.method, r.path, r.status, r.body, status, msg)
	}
}

// checkEnvelope checks the top-level fields Vault sends with every answer
// that carries data.
func (s *suite) checkEnvelope(t *testing.T, r *reply) {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(r.body, &top); err != nil {
		return // reported by do
	}
	for _, field := range []string{"request_id", "lease_id", "renewable", "lease_duration", "data", "wrap_info", "warnings", "auth"} {
		if _, ok := top[field]; !ok {
			t.Errorf("%s %s: answer lacks %q", r.method, r.path, field)
		}
	}
	if cc := r.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("%s %s: Cache-Control = %q, want no-store", r.method, r.path, cc)
	}
}
