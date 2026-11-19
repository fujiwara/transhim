package transhim_test

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/transhimtest"
)

const lookupPath = "/v1/auth/token/lookup-self"

func TestTokenLookup(t *testing.T) {
	var got []transhim.AuthRequest
	var events []transhim.AuditEvent
	e := newEnv(t,
		transhim.WithTokenLookup(),
		transhim.WithAuthorizer(func(ctx context.Context, req transhim.AuthRequest) error {
			got = append(got, req)
			return transhim.StaticTokenAuthorizer(testToken)(ctx, req)
		}),
		transhim.WithAuditHook(func(_ context.Context, ev transhim.AuditEvent) { events = append(events, ev) }),
	)

	r := e.do(http.MethodGet, lookupPath, "")
	if r.status != http.StatusOK {
		t.Fatalf("got %d %q, want 200", r.status, r.body)
	}
	// A token that does not expire and cannot be renewed: what a client
	// needs to leave it alone.
	const fields = "creation_ttl expire_time policies renewable ttl type"
	if f := strings.Join(slices.Sorted(maps.Keys(r.Data)), " "); f != fields {
		t.Errorf("data fields: got %s, want %s", f, fields)
	}
	for field, want := range map[string]any{"ttl": 0.0, "creation_ttl": 0.0, "renewable": false, "expire_time": nil, "type": "service"} {
		if r.Data[field] != want {
			t.Errorf("%s = %v, want %v", field, r.Data[field], want)
		}
	}
	if strings.Contains(string(r.body), testToken) {
		t.Error("the answer contains the token")
	}
	if len(got) != 1 || got[0].Op != transhim.OpTokenLookup || got[0].MountID != "" || got[0].KeyName != "" || got[0].Token != testToken {
		t.Errorf("auth requests = %+v, want one token_lookup without mount and key", got)
	}

	req := httptest.NewRequest(http.MethodGet, lookupPath, nil)
	req.Header.Set("X-Vault-Token", "wrong")
	e.wantError(e.send(req), 403, "permission denied")
	e.wantError(e.send(httptest.NewRequest(http.MethodGet, lookupPath, nil)), 403, "permission denied")

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		r := e.do(method, lookupPath, "")
		if r.status != http.StatusMethodNotAllowed || r.header.Get("Allow") != "GET" {
			t.Errorf("%s: got %d, Allow %q; want 405", method, r.status, r.header.Get("Allow"))
		}
	}
	// nothing else under auth/ is served
	for _, path := range []string{"/v1/auth/token/renew-self", "/v1/auth/token/lookup", lookupPath + "/", "/v1/auth/approle/login"} {
		e.wantError(e.do(http.MethodPost, path, ""), 404, "no handler for route")
	}

	if len(events) < 3 {
		t.Fatalf("got %d audit events", len(events))
	}
	for i, status := range []int{200, 403, 403} {
		if ev := events[i]; ev.Op != transhim.OpTokenLookup || ev.MountID != "" || ev.KeyName != "" || ev.Status != status {
			t.Errorf("audit event %d = %+v, want token_lookup with status %d", i, ev, status)
		}
	}
}

func TestTokenLookupDisabledByDefault(t *testing.T) {
	e := newEnv(t)
	e.wantError(e.do(http.MethodGet, lookupPath, ""), 404, "no handler for route")
}

func TestTokenLookupUnauthenticated(t *testing.T) {
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/transit", "m", transhimtest.NewFakeBackend()),
		transhim.AllowUnauthenticated(),
		transhim.WithTokenLookup(),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
	)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, handler: srv}
	if r := e.send(httptest.NewRequest(http.MethodGet, lookupPath, nil)); r.status != http.StatusOK {
		t.Errorf("got %d %q, want 200", r.status, r.body)
	}
}
