package transhim_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/transhimtest"
)

const (
	sseKey     = "1434f035-2747-4d60-a14f-5a0efa651729.4126.2"
	sseKeyPath = "/v1/transit-sse-s3/keys/" + sseKey
	// what RGW sends
	rgwCreateBody = `{"type":"chacha20-poly1305","derived":true}`
	rgwConfigBody = `{"deletion_allowed":true}`
)

func (e *env) want204(r *reply) {
	e.t.Helper()
	if r.status != http.StatusNoContent {
		e.t.Errorf("got %d %q, want 204", r.status, r.body)
	}
}

// TestRGWBucketKeyLifecycle replays what RGW does for SSE-S3 over the life of
// a bucket (docs/compat.md).
func TestRGWBucketKeyLifecycle(t *testing.T) {
	e := newEnv(t)
	datakeyPath := "/v1/transit-sse-s3/datakey/plaintext/" + sseKey
	decryptPath := "/v1/transit-sse-s3/decrypt/" + sseKey
	ctxBody := jsonBody(map[string]any{"context": rgwContext})

	// no key yet
	e.wantError(e.do(http.MethodPost, datakeyPath, ctxBody), 400, "encryption key not found")

	// first encrypted write: create, then datakey
	e.want204(e.do(http.MethodPost, sseKeyPath, rgwCreateBody))
	if !e.backend.HasKey("sse", sseKey) {
		t.Fatal("key was not created")
	}
	dk := e.do(http.MethodPost, datakeyPath, ctxBody)
	if dk.status != http.StatusOK {
		t.Fatalf("datakey: %d %q", dk.status, dk.body)
	}
	decBody := jsonBody(map[string]any{"context": rgwContext, "ciphertext": dk.str("ciphertext")})

	// after DeleteBucketEncryption RGW creates the same key again: the
	// existing key must survive, or old objects become unreadable
	e.want204(e.do(http.MethodPost, sseKeyPath, rgwCreateBody))
	if d := e.do(http.MethodPost, decryptPath, decBody); d.status != http.StatusOK || d.str("plaintext") != dk.str("plaintext") {
		t.Fatalf("decrypt after a second create: %d %q", d.status, d.body)
	}

	// DeleteBucket: config, then DELETE
	e.want204(e.do(http.MethodPost, sseKeyPath+"/config", rgwConfigBody))
	e.want204(e.do(http.MethodDelete, sseKeyPath, ""))
	if e.backend.HasKey("sse", sseKey) {
		t.Error("key was not deleted")
	}
	e.wantError(e.do(http.MethodPost, decryptPath, decBody), 400, "encryption key not found")

	// deleting again, and configuring a key that is gone, still succeed
	e.want204(e.do(http.MethodDelete, sseKeyPath, ""))
	e.want204(e.do(http.MethodPost, sseKeyPath+"/config", rgwConfigBody))
	if c, d := e.backend.Calls(transhimtest.OpCreateKey), e.backend.Calls(transhimtest.OpDeleteKey); c != 2 || d != 2 {
		t.Errorf("backend saw %d creates and %d deletes, want 2 and 2", c, d)
	}
}

func TestKeyOps(t *testing.T) {
	e := newEnv(t)
	t.Run("keys are per mount", func(t *testing.T) {
		e.want204(e.do(http.MethodPost, "/v1/transit-kms/keys/only-kms", ""))
		if !e.backend.HasKey("kms", "only-kms") || e.backend.HasKey("sse", "only-kms") {
			t.Error("key was not created in the kms mount only")
		}
		e.want204(e.do(http.MethodDelete, "/v1/transit-sse-s3/keys/only-kms", ""))
		if !e.backend.HasKey("kms", "only-kms") {
			t.Error("a delete on another mount removed the key")
		}
	})
	t.Run("PUT and bodies", func(t *testing.T) {
		e.want204(e.do(http.MethodPut, "/v1/transit-kms/keys/put-key", `{}`))
		e.want204(e.do(http.MethodPut, "/v1/transit-kms/keys/put-key/config", ``))
		e.want204(e.do(http.MethodPost, "/v1/transit-kms/keys/put-key/config", `{"deletion_allowed":false,"min_decryption_version":1}`))
		e.want204(e.do(http.MethodPost, "/v1/transit-kms/keys/put-key", `{"exportable":false,"type":"aes256-gcm96"}`))
		e.want204(e.do(http.MethodDelete, "/v1/transit-kms/keys/put-key", `{"ignored":true}`))
	})
	t.Run("escaped names", func(t *testing.T) {
		e.want204(e.do(http.MethodPost, "/v1/transit-kms/keys/tenant%24bucket", ""))
		if !e.backend.HasKey("kms", "tenant$bucket") {
			t.Error("key name was not unescaped")
		}
		e.want204(e.do(http.MethodPost, "/v1/transit-kms/keys/tenant%24bucket/config", rgwConfigBody))
		// a key may be called "config"
		e.want204(e.do(http.MethodPost, "/v1/transit-kms/keys/config", ""))
		if !e.backend.HasKey("kms", "config") {
			t.Error(`key "config" was not created`)
		}
		e.want204(e.do(http.MethodPost, "/v1/transit-kms/keys/config/config", rgwConfigBody))
	})
	t.Run("exportable is rejected", func(t *testing.T) {
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/keys/exp", `{"exportable":true}`), 400, "exportable keys are not supported")
		if e.backend.HasKey("kms", "exp") {
			t.Error("an exportable key was created")
		}
	})
	t.Run("bad requests", func(t *testing.T) {
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/keys/k", `{`), 400, "failed to decode JSON input")
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/keys/k/config", `{"deletion_allowed":"yes"}`), 400, "failed to decode JSON input")
		for _, path := range []string{"/v1/transit-kms/keys/", "/v1/transit-kms/keys/a/b", "/v1/transit-kms/keys/a%2Fb/config", "/v1/transit-kms/keys/a/b/config", "/v1/transit-kms/keys//config"} {
			r := e.do(http.MethodPost, path, "")
			if r.status != http.StatusBadRequest {
				t.Errorf("POST %s: got %d %q, want 400", path, r.status, r.body)
			}
		}
		r := e.do(http.MethodDelete, "/v1/transit-kms/keys/a/b", "")
		if r.status != http.StatusBadRequest {
			t.Errorf("DELETE with a slash: got %d %q, want 400", r.status, r.body)
		}
	})
	t.Run("methods", func(t *testing.T) {
		// reading keys is not part of v1
		for _, path := range []string{"/v1/transit-kms/keys/key1", "/v1/transit-kms/keys", "/v1/transit-kms/keys/"} {
			if r := e.do(http.MethodGet, path, ""); r.status != http.StatusNotFound {
				t.Errorf("GET %s: got %d, want 404", path, r.status)
			}
		}
		for method, path := range map[string]string{
			http.MethodPatch:  "/v1/transit-kms/keys/key1",
			http.MethodGet:    "/v1/transit-kms/keys/key1/config",
			http.MethodDelete: "/v1/transit-kms/keys/key1/config",
		} {
			r := e.do(method, path, "")
			if r.status != http.StatusMethodNotAllowed || r.header.Get("Allow") == "" {
				t.Errorf("%s %s: got %d, Allow %q; want 405", method, path, r.status, r.header.Get("Allow"))
			}
		}
		if !e.backend.HasKey("kms", "key1") {
			t.Error("key1 is gone")
		}
	})
	t.Run("backend errors", func(t *testing.T) {
		e.backend.SetError(transhimtest.OpCreateKey, &transhim.UpstreamError{Err: errors.New("SECRET"), Retryable: true})
		e.backend.SetError(transhimtest.OpDeleteKey, errors.New("SECRET"))
		defer e.backend.SetError(transhimtest.OpCreateKey, nil)
		defer e.backend.SetError(transhimtest.OpDeleteKey, nil)
		e.wantError(e.do(http.MethodPost, "/v1/transit-kms/keys/new", ""), 503, "upstream key service error")
		e.wantError(e.do(http.MethodDelete, "/v1/transit-kms/keys/key2", ""), 500, "internal error")
	})
}

func TestKeyOpsAuthorization(t *testing.T) {
	var got []transhim.AuthRequest
	deny := false
	e := newEnv(t, transhim.WithAuthorizer(func(_ context.Context, req transhim.AuthRequest) error {
		got = append(got, req)
		if deny {
			return transhim.ErrPermissionDenied
		}
		return nil
	}))
	e.do(http.MethodPost, "/v1/transit-sse-s3/keys/b1", rgwCreateBody)
	e.do(http.MethodPost, "/v1/transit-sse-s3/keys/b1/config", rgwConfigBody)
	e.do(http.MethodDelete, "/v1/transit-sse-s3/keys/b1", "")
	want := []transhim.Op{transhim.OpKeyCreate, transhim.OpKeyConfig, transhim.OpKeyDelete}
	if len(got) != len(want) {
		t.Fatalf("authorizer called %d times, want %d", len(got), len(want))
	}
	for i, op := range want {
		if got[i].Op != op || got[i].MountID != "sse" || got[i].KeyName != "b1" {
			t.Errorf("auth request %d = %+v, want op %s on sse/b1", i, got[i], op)
		}
	}

	deny = true
	e.wantError(e.do(http.MethodPost, "/v1/transit-sse-s3/keys/b2", rgwCreateBody), 403, "permission denied")
	e.wantError(e.do(http.MethodPost, "/v1/transit-sse-s3/keys/key1/config", rgwConfigBody), 403, "permission denied")
	e.wantError(e.do(http.MethodDelete, "/v1/transit-sse-s3/keys/key1", ""), 403, "permission denied")
	if e.backend.HasKey("sse", "b2") || !e.backend.HasKey("sse", "key1") {
		t.Error("a denied key operation reached the backend")
	}
}

// plainBackend hides the optional interfaces of the backend it wraps.
type plainBackend struct{ transhim.Backend }

func newPlainEnv(t *testing.T, opts ...transhim.MountOption) *env {
	t.Helper()
	fb := transhimtest.NewFakeBackend()
	fb.AddKey("m", "k")
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/transit", "m", plainBackend{fb}, opts...),
		transhim.AllowUnauthenticated(),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, backend: fb, handler: srv}
}

// TestUnmanagedKeyOps covers backends without KeyLifecycle, whose keys are
// provisioned in the KMS by other means.
func TestUnmanagedKeyOps(t *testing.T) {
	t.Run("accepted and ignored by default", func(t *testing.T) {
		e := newPlainEnv(t)
		e.want204(e.do(http.MethodPost, "/v1/transit/keys/new", rgwCreateBody))
		e.want204(e.do(http.MethodPost, "/v1/transit/keys/k/config", rgwConfigBody))
		e.want204(e.do(http.MethodDelete, "/v1/transit/keys/k", ""))
		if e.backend.HasKey("m", "new") || !e.backend.HasKey("m", "k") {
			t.Error("a key operation reached a backend without KeyLifecycle")
		}
		// exportable is rejected all the same
		e.wantError(e.do(http.MethodPost, "/v1/transit/keys/new", `{"exportable":true}`), 400, "exportable keys are not supported")
		if r := e.do(http.MethodPost, "/v1/transit/datakey/plaintext/k", ""); r.status != http.StatusOK {
			t.Errorf("datakey: %d %q", r.status, r.body)
		}
	})
	t.Run("RejectUnmanagedKeyOps", func(t *testing.T) {
		e := newPlainEnv(t, transhim.RejectUnmanagedKeyOps())
		e.wantError(e.do(http.MethodPost, "/v1/transit/keys/new", rgwCreateBody), 405, "unsupported operation")
		e.wantError(e.do(http.MethodPost, "/v1/transit/keys/k/config", rgwConfigBody), 405, "unsupported operation")
		e.wantError(e.do(http.MethodDelete, "/v1/transit/keys/k", ""), 405, "unsupported operation")
		if r := e.do(http.MethodPost, "/v1/transit/datakey/plaintext/k", ""); r.status != http.StatusOK {
			t.Errorf("datakey: %d %q", r.status, r.body)
		}
	})
	t.Run("RejectUnmanagedKeyOps does not affect a KeyLifecycle backend", func(t *testing.T) {
		fb := transhimtest.NewFakeBackend()
		srv, err := transhim.NewServer(
			transhim.Mount("/v1/transit", "m", fb, transhim.RejectUnmanagedKeyOps()),
			transhim.AllowUnauthenticated(),
		)
		if err != nil {
			t.Fatal(err)
		}
		e := &env{t: t, backend: fb, handler: srv}
		e.want204(e.do(http.MethodPost, "/v1/transit/keys/new", rgwCreateBody))
		if !fb.HasKey("m", "new") {
			t.Error("key was not created")
		}
	})
}

func TestRequireDeletionAllowed(t *testing.T) {
	fb := transhimtest.NewFakeBackend()
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/strict", "strict", fb, transhim.RequireDeletionAllowed()),
		transhim.Mount("/v1/lax", "lax", fb),
		transhim.AllowUnauthenticated(),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
	)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, backend: fb, handler: srv}
	const denied = "deletion is not allowed for this key"
	for _, name := range []string{"a", "b"} {
		e.want204(e.do(http.MethodPost, "/v1/strict/keys/"+name, ""))
	}

	e.wantError(e.do(http.MethodDelete, "/v1/strict/keys/a", ""), 400, denied)
	// the flag is per mount and per key
	e.want204(e.do(http.MethodPost, "/v1/lax/keys/a/config", rgwConfigBody))
	e.want204(e.do(http.MethodPost, "/v1/strict/keys/b/config", rgwConfigBody))
	e.wantError(e.do(http.MethodDelete, "/v1/strict/keys/a", ""), 400, denied)
	// a config without the field, or setting it to false, does not allow it
	e.want204(e.do(http.MethodPost, "/v1/strict/keys/a/config", `{}`))
	e.want204(e.do(http.MethodPost, "/v1/strict/keys/a/config", `{"deletion_allowed":false}`))
	e.wantError(e.do(http.MethodDelete, "/v1/strict/keys/a", ""), 400, denied)
	if !fb.HasKey("strict", "a") {
		t.Fatal("key was deleted without deletion_allowed")
	}

	e.want204(e.do(http.MethodPost, "/v1/strict/keys/a/config", rgwConfigBody))
	// taking it back works
	e.want204(e.do(http.MethodPost, "/v1/strict/keys/a/config", `{"deletion_allowed":false}`))
	e.wantError(e.do(http.MethodDelete, "/v1/strict/keys/a", ""), 400, denied)
	e.want204(e.do(http.MethodPost, "/v1/strict/keys/a/config", rgwConfigBody))
	e.want204(e.do(http.MethodDelete, "/v1/strict/keys/a", ""))
	if fb.HasKey("strict", "a") {
		t.Error("key was not deleted")
	}
	// the flag does not outlive the key
	e.want204(e.do(http.MethodPost, "/v1/strict/keys/a", ""))
	e.wantError(e.do(http.MethodDelete, "/v1/strict/keys/a", ""), 400, denied)

	// a failed delete keeps the flag, so the client can retry
	fb.SetError(transhimtest.OpDeleteKey, transhim.ErrUpstream)
	e.wantError(e.do(http.MethodDelete, "/v1/strict/keys/b", ""), 502, "upstream key service error")
	fb.SetError(transhimtest.OpDeleteKey, nil)
	e.want204(e.do(http.MethodDelete, "/v1/strict/keys/b", ""))

	// without the option no config is needed
	e.want204(e.do(http.MethodPost, "/v1/lax/keys/c", ""))
	e.want204(e.do(http.MethodDelete, "/v1/lax/keys/c", ""))
}
