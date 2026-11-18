package integration_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/transhimtest"
)

const (
	sopsMount = "sops"
	sopsKey   = "sops-key"
	sopsToken = "sops-test-token"
)

// sopsHarness is a transhim server for sops, plus the means to observe it.
type sopsHarness struct {
	t       *testing.T
	backend *transhimtest.FakeBackend
	url     string // the server's address
	dir     string

	mu      sync.Mutex
	events  []event
	methods []string
}

// newSopsHarness starts a server with one mount at /v1/transit, as sops users
// know it from Vault. It skips the test if there is no sops.
func newSopsHarness(t *testing.T) *sopsHarness {
	t.Helper()
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops is not installed")
	}
	h := &sopsHarness{t: t, backend: transhimtest.NewFakeBackend(), dir: t.TempDir()}
	h.backend.AddKey(sopsMount, sopsKey)
	srv, err := transhim.NewServer(
		// a KMS with provisioned keys: no KeyLifecycle
		transhim.Mount("/v1/transit", sopsMount, plainBackend{h.backend}),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(sopsToken)),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
		transhim.WithAuditHook(func(_ context.Context, ev transhim.AuditEvent) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.events = append(h.events, event{ev.Op, ev.MountID, ev.KeyName, ev.Status, string(ev.Context)})
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.methods = append(h.methods, r.Method+" "+r.URL.Path)
		h.mu.Unlock()
		srv.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	h.url = ts.URL
	return h
}

// take returns what the server saw since the last call: the audit events as
// "op status" strings, and the requests as "METHOD path".
func (h *sopsHarness) take() (evs, requests []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	evs, requests = ops(h.events, sopsMount), h.methods
	h.events, h.methods = nil, nil
	return evs, requests
}

// keyURI is how sops names a Transit key.
func (h *sopsHarness) keyURI(key string) string {
	return h.url + "/v1/transit/keys/" + key
}

// sops runs sops with the given token. The home directory is empty, so that
// nothing of the developer's (~/.vault-token, a .sops.yaml) gets in.
func (h *sopsHarness) sops(token string, args ...string) (stdout, stderr string, err error) {
	h.t.Helper()
	cmd := exec.Command("sops", args...)
	cmd.Dir = h.dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + h.dir,
		"VAULT_TOKEN=" + token,
		"SOPS_DISABLE_VERSION_CHECK=1",
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}

func (h *sopsHarness) write(name, content string) string {
	h.t.Helper()
	path := filepath.Join(h.dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return path
}

const sopsPlain = "db:\n    user: app\n    password: s3cret\n"

// TestSops runs sops (hc_vault_transit) against transhim: a client that uses
// encrypt instead of datakey, through Vault's Go client. docs/compat.md
// records what was seen.
func TestSops(t *testing.T) {
	h := newSopsHarness(t)
	h.write("plain.yaml", sopsPlain)

	// encrypt: sops wraps its data key with one encrypt call
	enc, stderr, err := h.sops(sopsToken, "encrypt", "--hc-vault-transit", h.keyURI(sopsKey), "plain.yaml")
	if err != nil {
		t.Fatalf("sops encrypt: %v\n%s", err, stderr)
	}
	if strings.Contains(enc, "s3cret") || !strings.Contains(enc, "enc: vault:v1:") {
		t.Errorf("the encrypted file does not look encrypted with a Transit key:\n%s", enc)
	}
	evs, reqs := h.take()
	if !slices.Equal(evs, []string{"encrypt 200"}) || !slices.Equal(reqs, []string{"PUT /v1/transit/encrypt/" + sopsKey}) {
		t.Errorf("sops encrypt caused %v (%v), want one PUT encrypt", evs, reqs)
	}
	h.write("enc.yaml", enc)

	// decrypt
	dec, stderr, err := h.sops(sopsToken, "decrypt", "enc.yaml")
	if err != nil {
		t.Fatalf("sops decrypt: %v\n%s", err, stderr)
	}
	if dec != sopsPlain {
		t.Errorf("sops decrypt = %q, want %q", dec, sopsPlain)
	}
	evs, reqs = h.take()
	if !slices.Equal(evs, []string{"decrypt 200"}) || !slices.Equal(reqs, []string{"PUT /v1/transit/decrypt/" + sopsKey}) {
		t.Errorf("sops decrypt caused %v (%v), want one PUT decrypt", evs, reqs)
	}

	// rotate: a new data key, wrapped again
	if _, stderr, err := h.sops(sopsToken, "rotate", "-i", "enc.yaml"); err != nil {
		t.Fatalf("sops rotate: %v\n%s", err, stderr)
	}
	if evs, _ := h.take(); !slices.Equal(evs, []string{"decrypt 200", "encrypt 200"}) {
		t.Errorf("sops rotate caused %v, want decrypt and encrypt", evs)
	}
	if dec, stderr, err := h.sops(sopsToken, "decrypt", "enc.yaml"); err != nil || dec != sopsPlain {
		t.Errorf("sops decrypt after rotate = %q, %v\n%s", dec, err, stderr)
	}
	h.take()
}

// TestSopsFailures: how sops reacts when the Transit endpoint refuses or
// fails.
func TestSopsFailures(t *testing.T) {
	h := newSopsHarness(t)
	h.write("plain.yaml", sopsPlain)
	enc, stderr, err := h.sops(sopsToken, "encrypt", "--hc-vault-transit", h.keyURI(sopsKey), "plain.yaml")
	if err != nil {
		t.Fatalf("sops encrypt: %v\n%s", err, stderr)
	}
	h.write("enc.yaml", enc)
	h.take()

	// lastLine is what sops tells its user in the end.
	lastLine := func(stderr string) string {
		lines := strings.Split(strings.TrimSpace(stderr), "\n")
		return strings.TrimSpace(lines[len(lines)-1])
	}

	t.Run("wrong token", func(t *testing.T) {
		out, stderr, err := h.sops("wrong", "decrypt", "enc.yaml")
		evs, _ := h.take()
		t.Logf("decrypt with a wrong token: %v after %v: %s", err, evs, lastLine(stderr))
		if err == nil || strings.Contains(out, "s3cret") {
			t.Errorf("sops decrypted with a wrong token")
		}
		if !slices.Equal(evs, []string{"decrypt 403"}) {
			t.Errorf("events = %v, want one refused decrypt", evs)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		_, stderr, err := h.sops(sopsToken, "encrypt", "--hc-vault-transit", h.keyURI("no-such-key"), "plain.yaml")
		evs, _ := h.take()
		t.Logf("encrypt with a missing key: %v after %v: %s", err, evs, lastLine(stderr))
		if err == nil {
			t.Error("sops encrypted with a key that does not exist")
		}
		// Vault would create the key here; transhim never does.
		if !slices.Equal(evs, []string{"encrypt 400"}) || h.backend.HasKey(sopsMount, "no-such-key") {
			t.Errorf("events = %v, want one refused encrypt and no key created", evs)
		}
	})

	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"key service down, retryable", &transhim.UpstreamError{Err: context.DeadlineExceeded, Retryable: true}, "decrypt 503"},
		{"key service error", &transhim.UpstreamError{Err: os.ErrInvalid}, "decrypt 502"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h.backend.SetError(transhimtest.OpDecrypt, tt.err)
			defer h.backend.SetError(transhimtest.OpDecrypt, nil)
			out, stderr, err := h.sops(sopsToken, "decrypt", "enc.yaml")
			evs, _ := h.take()
			t.Logf("decrypt: %v after %d requests %v: %s", err, len(evs), evs, lastLine(stderr))
			if err == nil || strings.Contains(out, "s3cret") {
				t.Error("sops decrypted although the key service failed")
			}
			if len(evs) == 0 || slices.ContainsFunc(evs, func(e string) bool { return e != tt.want }) {
				t.Errorf("events = %v, want only %q", evs, tt.want)
			}
		})
	}
}
