package transhim_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/transhimtest"
)

func TestAuditHook(t *testing.T) {
	var events []transhim.AuditEvent
	e := newEnv(t, cacheOption(false), transhim.WithAuditHook(func(_ context.Context, ev transhim.AuditEvent) {
		events = append(events, ev)
	}))
	begin := time.Now()
	e.backend.SetDelay(5 * time.Millisecond)

	dk := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", "")
	decBody := jsonBody(map[string]any{"ciphertext": dk.str("ciphertext")})
	e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", decBody)
	e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", decBody)
	e.do(http.MethodPost, "/v1/transit-kms/encrypt/nokey", jsonBody(map[string]any{"plaintext": b64("SECRET")}))
	e.do(http.MethodPost, "/v1/transit-sse-s3/keys/b1", rgwCreateBody)
	e.do(http.MethodPost, "/v1/transit-sse-s3/keys/b1/config", rgwConfigBody)
	e.do(http.MethodDelete, "/v1/transit-sse-s3/keys/b1", "")
	e.backend.SetError(transhimtest.OpDecrypt, errors.New("kms exploded"))
	e.do(http.MethodPost, "/v1/transit-kms/decrypt/key2", decBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/transit-kms/decrypt/key1", strings.NewReader(decBody))
	e.send(req) // no token
	e.do(http.MethodGet, "/v1/transit-kms/decrypt/key1", "")
	e.do(http.MethodPost, "/v1/transit-kms/decrypt/a%2Fb", "")
	e.do(http.MethodPost, "/v1/transit-kms/rewrap/key1", "")
	e.do(http.MethodGet, "/v1/sys/health", "")

	type want struct {
		op       transhim.Op
		mountID  string
		keyName  string
		status   int
		cacheHit bool
		err      string // substring of Err, "" for none
	}
	wants := []want{
		{transhim.OpDataKey, "kms", "key1", 200, false, ""},
		{transhim.OpDecrypt, "kms", "key1", 200, false, ""},
		{transhim.OpDecrypt, "kms", "key1", 200, true, ""},
		{transhim.OpEncrypt, "kms", "nokey", 400, false, "encryption key not found"},
		{transhim.OpKeyCreate, "sse", "b1", 204, false, ""},
		{transhim.OpKeyConfig, "sse", "b1", 204, false, ""},
		{transhim.OpKeyDelete, "sse", "b1", 204, false, ""},
		{transhim.OpDecrypt, "kms", "key2", 500, false, "kms exploded"}, // details are for the audit trail
		{transhim.OpDecrypt, "kms", "key1", 403, false, "permission denied"},
		{transhim.OpDecrypt, "kms", "", 405, false, "unsupported operation"},
		{transhim.OpDecrypt, "kms", "", 400, false, "invalid key name"},
		{"", "kms", "", 404, false, "unsupported path"},
		{"", "", "", 404, false, "no handler"},
	}
	if len(events) != len(wants) {
		t.Fatalf("got %d events, want %d", len(events), len(wants))
	}
	ids := map[string]bool{}
	for i, w := range wants {
		ev := events[i]
		if ev.Op != w.op || ev.MountID != w.mountID || ev.KeyName != w.keyName || ev.Status != w.status || ev.CacheHit != w.cacheHit {
			t.Errorf("event %d = %+v, want %+v", i, ev, w)
		}
		switch {
		case w.err == "" && ev.Err != nil:
			t.Errorf("event %d: Err = %v, want none", i, ev.Err)
		case w.err != "" && (ev.Err == nil || !strings.Contains(ev.Err.Error(), w.err)):
			t.Errorf("event %d: Err = %v, want %q", i, ev.Err, w.err)
		}
		if ev.Time.Before(begin) || ev.Time.After(time.Now()) || ev.Duration < 0 {
			t.Errorf("event %d: Time = %v, Duration = %v", i, ev.Time, ev.Duration)
		}
		if ev.RemoteAddr != "192.0.2.1:1234" || ev.RequestID == "" || ids[ev.RequestID] {
			t.Errorf("event %d: RemoteAddr = %q, RequestID = %q", i, ev.RemoteAddr, ev.RequestID)
		}
		ids[ev.RequestID] = true
	}
	// the backend call is part of the duration; a cache hit skips it
	if events[1].Duration < 5*time.Millisecond {
		t.Errorf("decrypt took %v, less than the backend's delay", events[1].Duration)
	}
	if !errors.Is(events[3].Err, transhim.ErrKeyNotFound) {
		t.Errorf("event 3: Err = %v, want ErrKeyNotFound", events[3].Err)
	}
	for i, ev := range events {
		if ev.Context != nil {
			t.Errorf("event %d: Context = %q, want none", i, ev.Context)
		}
	}
	// the request ID is the one the client got
	if !strings.Contains(string(dk.body), events[0].RequestID) {
		t.Errorf("request_id %q is not in the response %q", events[0].RequestID, dk.body)
	}
}

// The context names what a request is for (with Ceph RGW, the S3 object), also
// when the request is refused or answered from the cache.
func TestAuditContext(t *testing.T) {
	var events []transhim.AuditEvent
	e := newEnv(t, cacheOption(false), transhim.WithAuditHook(func(_ context.Context, ev transhim.AuditEvent) {
		events = append(events, ev)
	}))
	body := jsonBody(map[string]any{"context": rgwContext})
	dk := e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", body)
	decBody := jsonBody(map[string]any{"context": rgwContext, "ciphertext": dk.str("ciphertext")})
	e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", decBody)
	e.do(http.MethodPost, "/v1/transit-kms/decrypt/key1", decBody) // cache hit
	e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/nokey", body)
	e.send(httptest.NewRequest(http.MethodPost, "/v1/transit-kms/decrypt/key1", strings.NewReader(decBody))) // no token
	e.do(http.MethodPost, "/v1/transit-kms/datakey/plaintext/key1", `{"context":"***"}`)
	e.do(http.MethodPost, "/v1/transit-sse-s3/keys/b1", body)

	const s3Context = `{"aws:s3:arn":"arn:aws:s3::owner:bucket/object"}`
	wants := []struct {
		status  int
		context string
	}{
		{200, s3Context}, {200, s3Context}, {200, s3Context}, {400, s3Context}, {403, s3Context},
		{400, ""}, {204, ""},
	}
	if len(events) != len(wants) {
		t.Fatalf("got %d events, want %d", len(events), len(wants))
	}
	for i, w := range wants {
		if ev := events[i]; ev.Status != w.status || string(ev.Context) != w.context {
			t.Errorf("event %d: status %d, Context %q; want %d, %q", i, ev.Status, ev.Context, w.status, w.context)
		}
	}
	if !events[2].CacheHit {
		t.Error("event 2 is not a cache hit")
	}
}

func TestAuditHookNil(t *testing.T) {
	_, err := transhim.NewServer(
		transhim.Mount("/v1/t", "m", transhimtest.NewFakeBackend()),
		transhim.AllowUnauthenticated(),
		transhim.WithAuditHook(nil),
	)
	if err == nil {
		t.Error("NewServer accepted a nil audit hook")
	}
}
