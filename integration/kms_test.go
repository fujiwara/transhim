package integration_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/fujiwara/transhim"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	kmsv2 "k8s.io/kms/apis/v2"
)

const (
	kmsPluginBin = "vault-kubernetes-kms"
	k8sMount     = "k8s"
	k8sKey       = "kms"
	k8sToken     = "kms-test-token"
)

// syncBuffer collects the output of a running process. Unlike a bytes.Buffer
// it can be read while the process still writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// kmsPlugin is a vault-kubernetes-kms process: the KMS plugin kube-apiserver
// would talk to over a socket, with a Transit key served by transhim behind
// it.
type kmsPlugin struct {
	t      *testing.T
	socket string
	cmd    *exec.Cmd
	log    *syncBuffer
	exited chan struct{}
}

// startKMSPlugin runs the plugin against the Transit endpoint at transitURL.
// It does not wait for it. It skips the test if the plugin is not installed.
func startKMSPlugin(t *testing.T, transitURL, token string) *kmsPlugin {
	t.Helper()
	if _, err := exec.LookPath(kmsPluginBin); err != nil {
		t.Skip(kmsPluginBin + " is not installed")
	}
	dir := t.TempDir()
	p := &kmsPlugin{t: t, socket: filepath.Join(dir, "kms.sock"), log: &syncBuffer{}, exited: make(chan struct{})}
	_, healthPort, _ := strings.Cut(freeAddr(t), ":")
	p.cmd = exec.Command(kmsPluginBin,
		"-socket", "unix://"+p.socket,
		"-vault-address", transitURL,
		"-auth-method", "token", "-token", token,
		"-transit-mount", "transit", "-transit-key", k8sKey,
		"-token-refresh-interval", "1s",
		"-health-port", healthPort,
		"-disable-v1",
	)
	// nothing of the developer's environment (VAULT_ADDR, VAULT_TOKEN, ...)
	p.cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}
	p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.cmd.Wait(); close(p.exited) }()
	t.Cleanup(func() {
		p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.exited:
		case <-time.After(10 * time.Second):
			p.cmd.Process.Kill()
			<-p.exited
		}
	})
	return p
}

// client waits for the plugin's socket and returns a KMS v2 client on it.
func (p *kmsPlugin) client() kmsv2.KeyManagementServiceClient {
	p.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(p.socket); err == nil {
			break
		}
		select {
		case <-p.exited:
			p.t.Fatalf("the plugin exited:\n%s", p.log)
		default:
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("the plugin did not open its socket:\n%s", p.log)
		}
		time.Sleep(50 * time.Millisecond)
	}
	conn, err := grpc.NewClient("unix:"+p.socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { conn.Close() })
	return kmsv2.NewKeyManagementServiceClient(conn)
}

// TestKubernetesKMSPlugin runs vault-kubernetes-kms with its Transit key
// served by transhim, and talks to it the way kube-apiserver does (KMS v2).
// docs/compat.md records what was seen.
func TestKubernetesKMSPlugin(t *testing.T) {
	c := newClientServer(t, k8sMount, k8sKey, k8sToken, transhim.WithTokenLookup())
	p := startKMSPlugin(t, c.url, k8sToken)
	kms := p.client()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// Startup: the plugin checks its token, and does not start otherwise.
	if _, reqs := c.take(); !slices.Equal(reqs, []string{"GET /v1/auth/token/lookup-self"}) {
		t.Errorf("startup: %v, want the token lookup only", reqs)
	}

	// Status, which kube-apiserver polls: the key's version as the key ID,
	// and an encrypt and decrypt as a health check.
	st, err := kms.Status(ctx, &kmsv2.StatusRequest{})
	if err != nil {
		t.Fatalf("Status: %v\n%s", err, p.log)
	}
	if st.GetHealthz() != "ok" || st.GetKeyId() != "1" || st.GetVersion() != "v2" {
		t.Errorf("Status = %v, want ok with key ID 1", st)
	}
	evs, reqs := c.take()
	t.Logf("Status: %v", reqs)
	if want := []string{"key_read 200", "encrypt 200", "key_read 200", "decrypt 200"}; !slices.Equal(evs, want) {
		t.Errorf("Status caused %v, want %v", evs, want)
	}

	// A Secret's data key (seed) is wrapped and unwrapped.
	seed := []byte("a data encryption key seed")
	enc, err := kms.Encrypt(ctx, &kmsv2.EncryptRequest{Plaintext: seed, Uid: "uid-1"})
	if err != nil {
		t.Fatalf("Encrypt: %v\n%s", err, p.log)
	}
	if !strings.HasPrefix(string(enc.GetCiphertext()), "vault:v1:") || enc.GetKeyId() != "1" {
		t.Errorf("Encrypt = %q with key ID %q, want a vault:v1: ciphertext with key ID 1", enc.GetCiphertext(), enc.GetKeyId())
	}
	if evs, _ := c.take(); !slices.Equal(evs, []string{"encrypt 200", "key_read 200"}) {
		t.Errorf("Encrypt caused %v, want an encrypt and a key read", evs)
	}
	dec, err := kms.Decrypt(ctx, &kmsv2.DecryptRequest{Ciphertext: enc.GetCiphertext(), KeyId: enc.GetKeyId(), Uid: "uid-2"})
	if err != nil || !bytes.Equal(dec.GetPlaintext(), seed) {
		t.Fatalf("Decrypt = %q, %v; want the seed back\n%s", dec.GetPlaintext(), err, p.log)
	}
	if evs, _ := c.take(); !slices.Equal(evs, []string{"decrypt 200"}) {
		t.Errorf("Decrypt caused %v, want one decrypt", evs)
	}

	// The token is looked up again at every refresh interval. The answer
	// says that it does not expire, so the plugin never tries to renew it.
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, reqs := c.take()
		if slices.Contains(reqs, "GET /v1/auth/token/lookup-self") {
			break
		}
		if len(reqs) > 0 {
			t.Errorf("unexpected requests while idle: %v", reqs)
		}
		if time.Now().After(deadline) {
			t.Fatal("no second token lookup")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// A key the backend does not have: the plugin reports itself unhealthy.
	c.backend.RemoveKey(k8sMount, k8sKey)
	st, err = kms.Status(ctx, &kmsv2.StatusRequest{})
	if err != nil || st.GetHealthz() == "ok" {
		t.Errorf("Status without the key = %v, %v; want an unhealthy status", st, err)
	}
	if _, err := kms.Encrypt(ctx, &kmsv2.EncryptRequest{Plaintext: seed}); err == nil {
		t.Error("Encrypt without the key succeeded")
	}

	if log := p.log.String(); strings.Contains(log, `"level":"error"`) || strings.Contains(log, "attempting token renewal") {
		t.Errorf("the plugin logged errors or tried to renew its token:\n%s", log)
	}
}

// TestKubernetesKMSPluginRefused: the plugin does not start with a token the
// server refuses, or against a server that does not serve the token lookup.
func TestKubernetesKMSPluginRefused(t *testing.T) {
	for name, tt := range map[string]struct {
		opts  []transhim.Option
		token string
		want  string
	}{
		"wrong token":     {[]transhim.Option{transhim.WithTokenLookup()}, "wrong", "permission denied"},
		"no token lookup": {nil, k8sToken, "no handler for route"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newClientServer(t, k8sMount, k8sKey, k8sToken, tt.opts...)
			p := startKMSPlugin(t, c.url, tt.token)
			select {
			case <-p.exited:
			case <-time.After(15 * time.Second):
				t.Fatalf("the plugin kept running:\n%s", p.log)
			}
			if !strings.Contains(p.log.String(), tt.want) {
				t.Errorf("the plugin's log does not say %q:\n%s", tt.want, p.log)
			}
			if _, reqs := c.take(); !slices.Equal(reqs, []string{"GET /v1/auth/token/lookup-self"}) {
				t.Errorf("requests = %v, want the token lookup only", reqs)
			}
		})
	}
}
