package transhim_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/transhimtest"
)

func cacheOption(warm bool) transhim.Option {
	return transhim.WithDecryptCache(transhim.DecryptCacheConfig{MaxEntries: 100, TTL: time.Hour, WarmOnDatakey: warm})
}

// decryptCalls runs fn and returns how many backend decrypts it caused.
func (e *env) decryptCalls(fn func()) int {
	before := e.backend.Calls(transhimtest.OpDecrypt)
	fn()
	return e.backend.Calls(transhimtest.OpDecrypt) - before
}

func TestDecryptCache(t *testing.T) {
	e := newEnv(t, cacheOption(false))
	dk := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", jsonBody(map[string]any{"context": rgwContext}))
	ct := dk.str("ciphertext")
	body := jsonBody(map[string]any{"ciphertext": ct, "context": rgwContext})
	decrypt := func(path, body string) *reply { return e.do(http.MethodPost, path, body) }

	// RGW decrypts the same wrapped key over and over: one backend call
	n := e.decryptCalls(func() {
		for range 5 {
			d := decrypt("/v1/transit-kms/decrypt/key1", body)
			if d.status != http.StatusOK || d.str("plaintext") != dk.str("plaintext") {
				t.Fatalf("decrypt: %d %q", d.status, d.body)
			}
		}
	})
	if n != 1 {
		t.Errorf("5 identical decrypts called the backend %d times, want 1", n)
	}

	t.Run("a hit needs the same mount, key name, and context", func(t *testing.T) {
		n := e.decryptCalls(func() {
			e.wantError(decrypt("/v1/transit-kms/decrypt/key2", body), 400, "invalid ciphertext")
			e.wantError(decrypt("/v1/transit-sse-s3/decrypt/key1", body), 400, "invalid ciphertext")
			e.wantError(decrypt("/v1/transit-kms/decrypt/key1", jsonBody(map[string]any{"ciphertext": ct})), 400, "invalid ciphertext")
			e.wantError(decrypt("/v1/transit-kms/decrypt/key1", jsonBody(map[string]any{"ciphertext": ct, "context": b64("other")})), 400, "invalid ciphertext")
		})
		if n != 4 {
			t.Errorf("backend called %d times, want 4: none of these may be a hit", n)
		}
	})
	t.Run("failures are not cached", func(t *testing.T) {
		other := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key2", "")
		otherBody := jsonBody(map[string]any{"ciphertext": other.str("ciphertext")})
		e.backend.SetError(transhimtest.OpDecrypt, transhim.ErrUpstream)
		e.wantError(decrypt("/v1/transit-kms/decrypt/key2", otherBody), 502, "upstream key service error")
		e.backend.SetError(transhimtest.OpDecrypt, nil)
		n := e.decryptCalls(func() {
			if d := decrypt("/v1/transit-kms/decrypt/key2", otherBody); d.status != http.StatusOK {
				t.Errorf("decrypt after the failure: %d %q", d.status, d.body)
			}
		})
		if n != 1 {
			t.Errorf("backend called %d times after a failure, want 1", n)
		}
	})
	t.Run("datakey does not warm the cache by default", func(t *testing.T) {
		fresh := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", "")
		n := e.decryptCalls(func() {
			decrypt("/v1/transit-kms/decrypt/key1", jsonBody(map[string]any{"ciphertext": fresh.str("ciphertext")}))
		})
		if n != 1 {
			t.Errorf("backend called %d times, want 1", n)
		}
	})
}

func TestDecryptCacheWarmOnDatakey(t *testing.T) {
	e := newEnv(t, cacheOption(true))
	dk := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", jsonBody(map[string]any{"context": rgwContext}))
	n := e.decryptCalls(func() {
		d := e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", jsonBody(map[string]any{"ciphertext": dk.str("ciphertext"), "context": rgwContext}))
		if d.status != http.StatusOK || d.str("plaintext") != dk.str("plaintext") {
			t.Errorf("decrypt: %d %q", d.status, d.body)
		}
		// still bound to the context
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", jsonBody(map[string]any{"ciphertext": dk.str("ciphertext")})), 400, "invalid ciphertext")
	})
	if n != 1 {
		t.Errorf("backend called %d times, want 1 (only for the request without context)", n)
	}
}

// TestDecryptCacheInvalidation: deleting a key must take effect at once, even
// for plaintexts that are cached.
func TestDecryptCacheInvalidation(t *testing.T) {
	e := newEnv(t, cacheOption(true))
	e.want204(e.do(http.MethodPost, sseKeyPath, rgwCreateBody))
	bodies := map[string]string{}
	for _, path := range []string{"/v1/transit-sse-s3/datakey/plaintext/" + sseKey, "/v1/transit-sse-s3/datakey/plaintext/key1", "/v1/transit-kms/datakey/plaintext/key1"} {
		dk := e.do(http.MethodPost, path, "")
		bodies[path] = jsonBody(map[string]any{"ciphertext": dk.str("ciphertext")})
	}
	decrypt := func(key string) *reply {
		return e.do(http.MethodPost, "/v1/transit-sse-s3/decrypt/"+key, bodies["/v1/transit-sse-s3/datakey/plaintext/"+key])
	}
	if d := decrypt(sseKey); d.status != http.StatusOK {
		t.Fatalf("decrypt: %d %q", d.status, d.body)
	}

	e.want204(e.do(http.MethodDelete, sseKeyPath, ""))
	e.wantError(decrypt(sseKey), 400, "encryption key not found")

	// other keys keep their entries
	n := e.decryptCalls(func() {
		if d := decrypt("key1"); d.status != http.StatusOK {
			t.Errorf("decrypt of another key: %d %q", d.status, d.body)
		}
		d := e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", bodies["/v1/transit-kms/datakey/plaintext/key1"])
		if d.status != http.StatusOK {
			t.Errorf("decrypt in another mount: %d %q", d.status, d.body)
		}
	})
	if n != 0 {
		t.Errorf("backend called %d times: deleting one key emptied other entries", n)
	}
}

// TestDecryptCacheUnmanagedDelete: a delete invalidates even if the backend
// has no KeyLifecycle, since the key may have been removed in the KMS.
func TestDecryptCacheUnmanagedDelete(t *testing.T) {
	fb := transhimtest.NewFakeBackend()
	fb.AddKey("m", "k")
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/transit", "m", plainBackend{fb}),
		transhim.AllowUnauthenticated(),
		cacheOption(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, backend: fb, handler: srv}
	dk := e.do(http.MethodPost, "/v1/transit/datakey/plaintext/k", "")
	body := jsonBody(map[string]any{"ciphertext": dk.str("ciphertext")})
	e.want204(e.do(http.MethodDelete, "/v1/transit/keys/k", ""))
	if n := e.decryptCalls(func() { e.do(http.MethodPost, "/v1/transit/decrypt/k", body) }); n != 1 {
		t.Errorf("backend called %d times after the delete, want 1", n)
	}
}

// TestDecryptCacheStillAuthorizes: a cached plaintext must not be served to a
// request the authorizer rejects.
func TestDecryptCacheStillAuthorizes(t *testing.T) {
	var mu sync.Mutex
	deny := false
	e := newEnv(t, cacheOption(true), transhim.WithAuthorizer(func(context.Context, transhim.AuthRequest) error {
		mu.Lock()
		defer mu.Unlock()
		if deny {
			return transhim.ErrPermissionDenied
		}
		return nil
	}))
	dk := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", "")
	body := jsonBody(map[string]any{"ciphertext": dk.str("ciphertext")})
	if d := e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", body); d.status != http.StatusOK {
		t.Fatalf("decrypt: %d %q", d.status, d.body)
	}
	mu.Lock()
	deny = true
	mu.Unlock()
	e.wantError(e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", body), 403, "permission denied")
}

func TestDecryptCacheConfig(t *testing.T) {
	fb := transhimtest.NewFakeBackend()
	for name, cfg := range map[string]transhim.DecryptCacheConfig{
		"zero value":     {},
		"no TTL":         {MaxEntries: 10},
		"no MaxEntries":  {TTL: time.Minute},
		"negative TTL":   {MaxEntries: 10, TTL: -time.Second},
		"negative count": {MaxEntries: -1, TTL: time.Minute},
	} {
		_, err := transhim.NewServer(transhim.Mount("/v1/t", "m", fb), transhim.AllowUnauthenticated(), transhim.WithDecryptCache(cfg))
		if err == nil {
			t.Errorf("%s: NewServer succeeded", name)
		}
	}
}

func TestDecryptCacheConcurrent(t *testing.T) {
	e := newEnv(t, transhim.WithDecryptCache(transhim.DecryptCacheConfig{MaxEntries: 8, TTL: time.Hour, WarmOnDatakey: true}))
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			key := "/v1/transit-sse-s3/keys/bucket" + string(rune('0'+g%2))
			name := key[len("/v1/transit-sse-s3/keys/"):]
			for range 30 {
				e.do(http.MethodPost, key, rgwCreateBody)
				dk := e.do(http.MethodPost, "/v1/transit-sse-s3/datakey/plaintext/"+name, "")
				if dk.status != http.StatusOK {
					continue // the other goroutine deleted the key
				}
				d := e.do(http.MethodPost, "/v1/transit-sse-s3/decrypt/"+name, jsonBody(map[string]any{"ciphertext": dk.str("ciphertext")}))
				if d.status == http.StatusOK && d.str("plaintext") != dk.str("plaintext") {
					t.Errorf("decrypt returned another plaintext")
				}
				e.do(http.MethodDelete, key, "")
			}
		})
	}
	wg.Wait()
}
