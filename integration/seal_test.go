package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/transhimtest"
)

const (
	sealMount = "seal"
	sealKey   = "autounseal"
	sealToken = "seal-test-token"
)

// sealedBao is an OpenBao server whose seal is a Transit key served by
// transhim (seal "transit", which is the go-kms-wrapping transit wrapper).
type sealedBao struct {
	t      *testing.T
	config string
	addr   string // the OpenBao API address
	cmd    *exec.Cmd
	log    *bytes.Buffer
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// newSealedBao writes the configuration of an OpenBao server sealed by the
// key sealKey of the Transit endpoint at transitURL. It skips the test if
// there is no bao.
func newSealedBao(t *testing.T, transitURL string) *sealedBao {
	t.Helper()
	if _, err := exec.LookPath("bao"); err != nil {
		t.Skip("bao (OpenBao) is not installed")
	}
	dir := t.TempDir()
	b := &sealedBao{t: t, config: filepath.Join(dir, "config.hcl"), addr: freeAddr(t), log: &bytes.Buffer{}}
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`
storage "raft" {
  path    = %q
  node_id = "node1"
}
listener "tcp" {
  address     = %q
  tls_disable = true
}
seal "transit" {
  address    = %q
  token      = %q
  key_name   = %q
  mount_path = "transit/"
}
api_addr     = "http://%s"
cluster_addr = "http://%s"
ui           = false
`, data, b.addr, transitURL, sealToken, sealKey, b.addr, freeAddr(t))
	if err := os.WriteFile(b.config, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.stop)
	return b
}

// start runs the server. It does not wait for it.
func (b *sealedBao) start() {
	b.t.Helper()
	b.cmd = exec.Command("bao", "server", "-config="+b.config)
	// nothing of the developer's environment (BAO_ADDR, VAULT_TOKEN, ...)
	b.cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Dir(b.config)}
	b.cmd.Stdout, b.cmd.Stderr = b.log, b.log
	if err := b.cmd.Start(); err != nil {
		b.t.Fatal(err)
	}
}

func (b *sealedBao) stop() {
	if b.cmd == nil || b.cmd.Process == nil {
		return
	}
	b.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { b.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		b.cmd.Process.Kill()
		<-done
	}
	b.cmd = nil
}

type sealStatus struct {
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
}

// status asks the server for its seal status.
func (b *sealedBao) status() (sealStatus, error) {
	var st sealStatus
	res, err := http.Get("http://" + b.addr + "/v1/sys/seal-status")
	if err != nil {
		return st, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return st, fmt.Errorf("seal-status: %s", res.Status)
	}
	return st, json.NewDecoder(res.Body).Decode(&st)
}

// waitFor waits until the server reports a status that ok accepts.
func (b *sealedBao) waitFor(what string, ok func(sealStatus) bool) sealStatus {
	b.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var st sealStatus
	var err error
	for time.Now().Before(deadline) {
		if st, err = b.status(); err == nil && ok(st) {
			return st
		}
		time.Sleep(200 * time.Millisecond)
	}
	b.t.Fatalf("OpenBao did not get %s: last status %+v, %v\n%s", what, st, err, b.log)
	return st
}

// init initializes the server. With an auto-unseal seal there are no unseal
// keys to enter: the server unseals itself through the Transit key.
func (b *sealedBao) init() {
	b.t.Helper()
	req, _ := http.NewRequest(http.MethodPut, "http://"+b.addr+"/v1/sys/init",
		strings.NewReader(`{"recovery_shares":1,"recovery_threshold":1}`))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		RootToken string `json:"root_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || res.StatusCode != http.StatusOK || out.RootToken == "" {
		b.t.Fatalf("init: %s, %v\n%s", res.Status, err, b.log)
	}
}

// TestOpenBaoTransitSeal runs OpenBao with its seal on a Transit key served
// by transhim: the go-kms-wrapping transit wrapper as a client. docs/compat.md
// records what was seen.
func TestOpenBaoTransitSeal(t *testing.T) {
	c := newClientServer(t, sealMount, sealKey, sealToken)
	b := newSealedBao(t, c.url)

	// Start: the wrapper tries to renew its token, which transhim does not
	// serve, and goes on.
	b.start()
	st := b.waitFor("up", func(sealStatus) bool { return true })
	if st.Type != "transit" || st.Initialized || !st.Sealed {
		t.Fatalf("status of a new server = %+v, want an uninitialized, sealed transit seal", st)
	}
	evs, reqs := c.take()
	if len(reqs) == 0 || reqs[0] != "PUT /v1/auth/token/renew-self" {
		t.Errorf("first request = %v, want the token renewal", reqs)
	}
	for _, r := range reqs {
		if !strings.HasPrefix(r, "PUT /v1/transit/encrypt/"+sealKey) && r != "PUT /v1/auth/token/renew-self" {
			t.Errorf("unexpected request at startup: %s", r)
		}
	}
	t.Logf("startup: %v", reqs)

	// Init: the root key is wrapped with the Transit key, and the server
	// unseals itself.
	b.init()
	b.waitFor("unsealed after init", func(st sealStatus) bool { return st.Initialized && !st.Sealed })
	evs, reqs = c.take()
	t.Logf("init: %v", evs)
	if !slices.Contains(evs, "encrypt 200") || slices.ContainsFunc(evs, func(e string) bool { return !strings.HasSuffix(e, " 200") }) {
		t.Errorf("init caused %v, want successful encrypts", evs)
	}
	for _, r := range reqs {
		if !strings.HasPrefix(r, "PUT /v1/transit/") {
			t.Errorf("unexpected request during init: %s", r)
		}
	}

	// Restart: the server unseals itself by decrypting the stored key.
	b.stop()
	c.take()
	b.start()
	b.waitFor("unsealed after a restart", func(st sealStatus) bool { return st.Initialized && !st.Sealed })
	evs, _ = c.take()
	t.Logf("restart: %v", evs)
	if !slices.Contains(evs, "decrypt 200") {
		t.Errorf("restart caused %v, want a decrypt", evs)
	}
	if n := c.backend.Calls(transhimtest.OpGenerateDataKey); n != 0 {
		t.Errorf("%d data key calls, want none: the seal uses encrypt and decrypt only", n)
	}
}

// TestOpenBaoTransitSealFailure: a server whose Transit key cannot be used
// stays sealed.
func TestOpenBaoTransitSealFailure(t *testing.T) {
	c := newClientServer(t, sealMount, sealKey, sealToken)
	b := newSealedBao(t, c.url)
	b.start()
	b.waitFor("up", func(sealStatus) bool { return true })
	b.init()
	b.waitFor("unsealed after init", func(st sealStatus) bool { return st.Initialized && !st.Sealed })
	b.stop()
	c.take()

	c.backend.SetError(transhimtest.OpDecrypt, &transhim.UpstreamError{Err: context.DeadlineExceeded, Retryable: true})
	b.start()
	// It either stays sealed or does not come up at all. Give it the time a
	// working server needs several times over.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := b.status(); err == nil && !st.Sealed {
			t.Fatalf("OpenBao unsealed although the Transit key could not decrypt: %+v", st)
		}
		time.Sleep(200 * time.Millisecond)
	}
	st, err := b.status()
	evs, _ := c.take()
	t.Logf("with a failing key service: status %+v, %v; %d requests %v", st, err, len(evs), evs)
	if !slices.Contains(evs, "decrypt 503") {
		t.Errorf("events = %v, want a failed decrypt", evs)
	}

	// The key service is back: a restart unseals.
	c.backend.SetError(transhimtest.OpDecrypt, nil)
	b.stop()
	b.start()
	b.waitFor("unsealed once the key service is back", func(st sealStatus) bool { return st.Initialized && !st.Sealed })
}
