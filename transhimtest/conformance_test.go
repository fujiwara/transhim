package transhimtest_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/hierarchical"
	"github.com/fujiwara/transhim/keystore/memstore"
	"github.com/fujiwara/transhim/transhimtest"
)

const token = "conformance-token"

// plainBackend hides the optional interfaces of the backend it wraps.
type plainBackend struct{ transhim.Backend }

func newServer(t *testing.T, opts ...transhim.Option) *transhim.Server {
	t.Helper()
	srv, err := transhim.NewServer(append(opts, transhim.WithLogger(slog.New(slog.DiscardHandler)))...)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestConformance(t *testing.T) {
	auth := transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(token))
	cache := transhim.WithDecryptCache(transhim.DecryptCacheConfig{MaxEntries: 100, TTL: time.Hour, WarmOnDatakey: true})

	t.Run("fake backend", func(t *testing.T) {
		srv := newServer(t, transhim.Mount("/v1/transit", "m", transhimtest.NewFakeBackend()), auth)
		transhimtest.RunConformance(t, transhimtest.Conformance{Handler: srv, Prefix: "/v1/transit", Token: token, ManagedKeys: true})
	})
	t.Run("fake backend with decrypt cache", func(t *testing.T) {
		srv := newServer(t, transhim.Mount("/v1/transit", "m", transhimtest.NewFakeBackend()), auth, cache)
		transhimtest.RunConformance(t, transhimtest.Conformance{Handler: srv, Prefix: "/v1/transit", Token: token, ManagedKeys: true})
	})
	t.Run("data key generator", func(t *testing.T) {
		srv := newServer(t, transhim.Mount("/v1/transit", "m", transhimtest.NewFakeBackend().WithDataKeyGenerator()), auth, cache)
		transhimtest.RunConformance(t, transhimtest.Conformance{Handler: srv, Prefix: "/v1/transit", Token: token, ManagedKeys: true})
	})
	t.Run("hierarchical backend", func(t *testing.T) {
		root := transhimtest.NewFakeBackend()
		root.AddKey("rgw-sse-s3", "root")
		b, err := hierarchical.New(root, "root", memstore.New())
		if err != nil {
			t.Fatal(err)
		}
		srv := newServer(t, transhim.Mount("/v1/transit-sse-s3", "rgw-sse-s3", b), auth, cache)
		transhimtest.RunConformance(t, transhimtest.Conformance{Handler: srv, Prefix: "/v1/transit-sse-s3", Token: token, ManagedKeys: true})
	})
	t.Run("pre-provisioned keys", func(t *testing.T) {
		fb := transhimtest.NewFakeBackend()
		fb.AddKey("m", "key-a")
		fb.AddKey("m", "key-b")
		for name, opts := range map[string][]transhim.MountOption{
			"key operations ignored": nil,
			"key operations refused": {transhim.RejectUnmanagedKeyOps()},
		} {
			t.Run(name, func(t *testing.T) {
				srv := newServer(t, transhim.Mount("/v1/transit", "m", plainBackend{fb}, opts...), auth, cache)
				transhimtest.RunConformance(t, transhimtest.Conformance{
					Handler: srv, Prefix: "/v1/transit", Token: token, KeyNames: [2]string{"key-a", "key-b"},
				})
			})
		}
	})
	t.Run("without authorization, other limits", func(t *testing.T) {
		srv := newServer(t,
			transhim.Mount("transit/", "m", transhimtest.NewFakeBackend(), transhim.WithMaxPlaintextSize(100)),
			transhim.AllowUnauthenticated(),
		)
		transhimtest.RunConformance(t, transhimtest.Conformance{Handler: srv, Prefix: "transit", ManagedKeys: true, MaxPlaintextSize: 100})
	})
}

// TestConformanceDetectsViolations makes sure the suite is not vacuous: a
// server that breaks the contract must fail it.
func TestConformanceDetectsViolations(t *testing.T) {
	auth := transhim.WithAuthorizer(transhim.StaticTokenAuthorizer(token))
	for name, backend := range map[string]transhim.Backend{
		"AAD is not bound":       ignoreAAD{transhimtest.NewFakeBackend()},
		"delete leaves the key":  keepKeys{transhimtest.NewFakeBackend()},
		"create replaces a key":  replaceKeys{transhimtest.NewFakeBackend()},
		"missing key is unknown": hideNotFound{transhimtest.NewFakeBackend()},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newServer(t, transhim.Mount("/v1/transit", "m", backend), auth)
			if !fails(func(t *testing.T) {
				transhimtest.RunConformance(t, transhimtest.Conformance{Handler: srv, Prefix: "/v1/transit", Token: token, ManagedKeys: true})
			}) {
				t.Error("the conformance suite passed a broken backend")
			}
		})
	}
}
