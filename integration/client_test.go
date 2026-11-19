package integration_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/transhimtest"
)

// clientServer is a transhim server for a Transit client other than RGW,
// plus the means to observe it. It has one mount at /v1/transit, where such
// clients expect Vault's Transit engine, on a KMS-like backend with one key.
type clientServer struct {
	backend *transhimtest.FakeBackend
	mountID string
	url     string // the server's address

	mu       sync.Mutex
	events   []event
	requests []string
}

func newClientServer(t *testing.T, mountID, key, token string, opts ...transhim.Option) *clientServer {
	t.Helper()
	c := &clientServer{backend: transhimtest.NewFakeBackend(), mountID: mountID}
	c.backend.AddKey(mountID, key)
	srv, err := transhim.NewServer(append(opts,
		// a KMS with provisioned keys: no KeyLifecycle, no KeyDescriber
		transhim.Mount("/v1/transit", mountID, plainBackend{c.backend}),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(token)),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
		transhim.WithAuditHook(func(_ context.Context, ev transhim.AuditEvent) {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.events = append(c.events, event{ev.Op, ev.MountID, ev.KeyName, ev.Status, string(ev.Context)})
		}),
	)...)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.requests = append(c.requests, r.Method+" "+r.URL.Path)
		c.mu.Unlock()
		srv.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	c.url = ts.URL
	return c
}

// take returns what the server saw since the last call: the audit events of
// the mount as "op status" strings, and all requests as "METHOD path".
func (c *clientServer) take() (evs, requests []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	evs, requests = ops(c.events, c.mountID), c.requests
	c.events, c.requests = nil, nil
	return evs, requests
}
