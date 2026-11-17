package hierarchical_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/hierarchical"
	"github.com/fujiwara/transhim/keystore/memstore"
	"github.com/fujiwara/transhim/transhimtest"
)

const (
	rootKey = "root-key"
	mountID = "rgw-sse-s3"
	bucket  = "1434f035-2747-4d60-a14f-5a0efa651729.4126.2"
)

// recordingRoot records the requests the root backend gets.
type recordingRoot struct {
	*transhimtest.FakeBackend
	mu       sync.Mutex
	encrypts []transhim.EncryptRequest
	decrypts []transhim.DecryptRequest
}

func (r *recordingRoot) Encrypt(ctx context.Context, req transhim.EncryptRequest) (transhim.WrappedKey, error) {
	r.mu.Lock()
	r.encrypts = append(r.encrypts, transhim.EncryptRequest{MountID: req.MountID, KeyName: req.KeyName, AAD: bytes.Clone(req.AAD), Plaintext: bytes.Clone(req.Plaintext)})
	r.mu.Unlock()
	return r.FakeBackend.Encrypt(ctx, req)
}

func (r *recordingRoot) Decrypt(ctx context.Context, req transhim.DecryptRequest) ([]byte, error) {
	r.mu.Lock()
	r.decrypts = append(r.decrypts, req)
	r.mu.Unlock()
	return r.FakeBackend.Decrypt(ctx, req)
}

type fixture struct {
	root  *recordingRoot
	store *memstore.Store
	b     *hierarchical.Backend
}

func newFixture(t *testing.T, opts ...hierarchical.Option) *fixture {
	t.Helper()
	fb := transhimtest.NewFakeBackend()
	fb.AddKey(mountID, rootKey)
	fb.AddKey("other-mount", rootKey)
	f := &fixture{root: &recordingRoot{FakeBackend: fb}, store: memstore.New()}
	b, err := hierarchical.New(f.root, rootKey, f.store, opts...)
	if err != nil {
		t.Fatal(err)
	}
	f.b = b
	return f
}

func (f *fixture) rootCalls() (encrypts, decrypts int) {
	return f.root.Calls(transhimtest.OpEncrypt), f.root.Calls(transhimtest.OpDecrypt)
}

func encrypt(t *testing.T, b transhim.Backend, name, plaintext, aad string) transhim.WrappedKey {
	t.Helper()
	wk, err := b.Encrypt(t.Context(), transhim.EncryptRequest{MountID: mountID, KeyName: name, Plaintext: []byte(plaintext), AAD: []byte(aad)})
	if err != nil {
		t.Fatalf("Encrypt with %q: %v", name, err)
	}
	return wk
}

func decrypt(t *testing.T, b transhim.Backend, name string, wk transhim.WrappedKey, aad string) ([]byte, error) {
	t.Helper()
	return b.Decrypt(t.Context(), transhim.DecryptRequest{MountID: mountID, KeyName: name, Wrapped: wk, AAD: []byte(aad)})
}

func TestRoundTrip(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	if err := f.b.CreateKey(ctx, mountID, bucket); err != nil {
		t.Fatal(err)
	}
	wk := encrypt(t, f.b, bucket, "data key", "aad")
	if wk.KeyRef != "h1" || wk.Version != 1 {
		t.Errorf("wrapped key = %+v, want KeyRef h1 and Version 1", wk)
	}
	// Blob = 12 byte nonce || ciphertext || 16 byte tag
	if len(wk.Blob) != 12+len("data key")+16 || bytes.Contains(wk.Blob, []byte("data key")) {
		t.Errorf("blob is %d bytes: %x", len(wk.Blob), wk.Blob)
	}
	got, err := decrypt(t, f.b, bucket, wk, "aad")
	if err != nil || string(got) != "data key" {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}
	if again := encrypt(t, f.b, bucket, "data key", "aad"); bytes.Equal(again.Blob, wk.Blob) {
		t.Error("two encryptions of the same plaintext are identical")
	}
	if wk := encrypt(t, f.b, bucket, "", "aad"); len(wk.Blob) != 12+16 {
		t.Errorf("empty plaintext: blob is %d bytes", len(wk.Blob))
	}

	if err := f.b.CreateKey(ctx, mountID, "other"); err != nil {
		t.Fatal(err)
	}
	tampered := wk
	tampered.Blob = bytes.Clone(wk.Blob)
	tampered.Blob[len(tampered.Blob)-1] ^= 1
	mismatches := map[string]func() ([]byte, error){
		"wrong AAD": func() ([]byte, error) { return decrypt(t, f.b, bucket, wk, "other") },
		"wrong key": func() ([]byte, error) { return decrypt(t, f.b, "other", wk, "aad") },
		"tampered":  func() ([]byte, error) { return decrypt(t, f.b, bucket, tampered, "aad") },
		"short blob": func() ([]byte, error) {
			return decrypt(t, f.b, bucket, transhim.WrappedKey{KeyRef: "h1", Blob: wk.Blob[:27]}, "aad")
		},
		"empty blob": func() ([]byte, error) { return decrypt(t, f.b, bucket, transhim.WrappedKey{KeyRef: "h1"}, "aad") },
		"foreign ref": func() ([]byte, error) {
			return decrypt(t, f.b, bucket, transhim.WrappedKey{KeyRef: "fake", Blob: wk.Blob}, "aad")
		},
	}
	for name, fn := range mismatches {
		if _, err := fn(); !errors.Is(err, transhim.ErrCiphertextMismatch) {
			t.Errorf("%s: err = %v, want ErrCiphertextMismatch", name, err)
		}
	}
}

func TestKeyNotFound(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	// no lazy creation
	if _, err := f.b.Encrypt(ctx, transhim.EncryptRequest{MountID: mountID, KeyName: bucket}); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("Encrypt without a key: err = %v, want ErrKeyNotFound", err)
	}
	if _, err := decrypt(t, f.b, bucket, transhim.WrappedKey{KeyRef: "h1", Blob: make([]byte, 40)}, ""); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("Decrypt without a key: err = %v, want ErrKeyNotFound", err)
	}
	if f.store.Len() != 0 {
		t.Error("a key was created lazily")
	}
	// keys are per mount ID
	if err := f.b.CreateKey(ctx, "other-mount", bucket); err != nil {
		t.Fatal(err)
	}
	if _, err := f.b.Encrypt(ctx, transhim.EncryptRequest{MountID: mountID, KeyName: bucket}); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("Encrypt with a key of another mount: err = %v, want ErrKeyNotFound", err)
	}
}

// TestRootCalls checks what the root backend gets to see and how often.
func TestRootCalls(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	if err := f.b.CreateKey(ctx, mountID, bucket); err != nil {
		t.Fatal(err)
	}
	wantAAD := []byte("transhim/hierarchical/v1\x00" + mountID + "\x00" + bucket)
	if got := hierarchical.RootAAD(mountID, bucket); !bytes.Equal(got, wantAAD) {
		t.Fatalf("root AAD = %q, want %q", got, wantAAD)
	}
	if len(f.root.encrypts) != 1 {
		t.Fatalf("root Encrypt called %d times, want 1", len(f.root.encrypts))
	}
	enc := f.root.encrypts[0]
	if enc.MountID != mountID || enc.KeyName != rootKey || !bytes.Equal(enc.AAD, wantAAD) || len(enc.Plaintext) != 32 {
		t.Errorf("root Encrypt request = %+v (%d plaintext bytes)", enc, len(enc.Plaintext))
	}

	// the key created just now is already in memory: no root call
	wk := encrypt(t, f.b, bucket, "p", "aad")
	for range 10 {
		if _, err := decrypt(t, f.b, bucket, wk, "aad"); err != nil {
			t.Fatal(err)
		}
	}
	if e, d := f.rootCalls(); e != 1 || d != 0 {
		t.Errorf("root calls = %d encrypts, %d decrypts; want 1, 0", e, d)
	}

	// another instance (or this one after a restart) unwraps once
	other, err := hierarchical.New(f.root, rootKey, f.store)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if got, err := decrypt(t, other, bucket, wk, "aad"); err != nil || string(got) != "p" {
			t.Fatalf("Decrypt on another instance = %q, %v", got, err)
		}
	}
	if e, d := f.rootCalls(); e != 1 || d != 1 {
		t.Errorf("root calls = %d encrypts, %d decrypts; want 1, 1", e, d)
	}
	dec := f.root.decrypts[0]
	if dec.MountID != mountID || dec.KeyName != rootKey || !bytes.Equal(dec.AAD, wantAAD) {
		t.Errorf("root Decrypt request = %+v", dec)
	}
	stored, _ := f.store.Get(ctx, mountID, bucket)
	if !bytes.Equal(dec.Wrapped.Blob, stored.Wrapped.Blob) || stored.CreatedAt.IsZero() {
		t.Errorf("stored key = %+v", stored)
	}
	// the intermediate key is stored wrapped, never in the clear
	if bytes.Contains(stored.Wrapped.Blob, enc.Plaintext) {
		t.Error("the store holds the intermediate key in plaintext")
	}
}

func TestCreateKeyIsIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	if err := f.b.CreateKey(ctx, mountID, bucket); err != nil {
		t.Fatal(err)
	}
	wk := encrypt(t, f.b, bucket, "p", "aad")
	before, _ := f.store.Get(ctx, mountID, bucket)

	// RGW creates the key again after DeleteBucketEncryption
	for range 3 {
		if err := f.b.CreateKey(ctx, mountID, bucket); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := f.store.Get(ctx, mountID, bucket)
	if !bytes.Equal(before.Wrapped.Blob, after.Wrapped.Blob) {
		t.Fatal("CreateKey replaced an existing key")
	}
	if got, err := decrypt(t, f.b, bucket, wk, "aad"); err != nil || string(got) != "p" {
		t.Errorf("Decrypt after creating again = %q, %v", got, err)
	}
	if e, _ := f.rootCalls(); e != 1 {
		t.Errorf("root Encrypt called %d times, want 1: an existing key needs no root call", e)
	}
}

// racingStore lets every CreateKey see "not found" first, so that all of them
// race on PutIfAbsent.
type racingStore struct {
	*memstore.Store
	armed atomic.Bool
	ready sync.WaitGroup
	start chan struct{}
}

func (s *racingStore) Get(ctx context.Context, mountID, keyName string) (hierarchical.StoredKey, error) {
	k, err := s.Store.Get(ctx, mountID, keyName)
	if s.armed.Load() {
		s.ready.Done()
		<-s.start
	}
	return k, err
}

func TestConcurrentCreateKey(t *testing.T) {
	ctx := t.Context()
	fb := transhimtest.NewFakeBackend()
	fb.AddKey(mountID, rootKey)
	store := &racingStore{Store: memstore.New(), start: make(chan struct{})}
	const n = 16
	store.armed.Store(true)
	store.ready.Add(n)
	backends := make([]*hierarchical.Backend, n)
	var wg sync.WaitGroup
	for i := range backends {
		b, err := hierarchical.New(fb, rootKey, store)
		if err != nil {
			t.Fatal(err)
		}
		backends[i] = b
		wg.Go(func() {
			if err := b.CreateKey(ctx, mountID, bucket); err != nil {
				t.Errorf("CreateKey: %v", err)
			}
		})
	}
	store.ready.Wait() // all of them have seen that there is no key
	store.armed.Store(false)
	close(store.start)
	wg.Wait()
	if store.Len() != 1 {
		t.Fatalf("%d keys stored, want 1", store.Len())
	}
	if e := fb.Calls(transhimtest.OpEncrypt); e != n {
		t.Fatalf("root Encrypt called %d times, want %d: the calls did not race", e, n)
	}
	// every instance must end up with the one stored key, winner or not
	wk := encrypt(t, backends[0], bucket, "p", "aad")
	for i, b := range backends {
		if got, err := decrypt(t, b, bucket, wk, "aad"); err != nil || string(got) != "p" {
			t.Errorf("instance %d: Decrypt = %q, %v", i, got, err)
		}
	}
}

func TestDeleteKey(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	for _, name := range []string{bucket, "other"} {
		if err := f.b.CreateKey(ctx, mountID, name); err != nil {
			t.Fatal(err)
		}
	}
	wk := encrypt(t, f.b, bucket, "p", "aad")
	otherWK := encrypt(t, f.b, "other", "p", "aad")

	for range 2 { // idempotent
		if err := f.b.DeleteKey(ctx, mountID, bucket); err != nil {
			t.Fatal(err)
		}
	}
	if f.store.Len() != 1 {
		t.Errorf("%d keys stored, want 1", f.store.Len())
	}
	if _, err := decrypt(t, f.b, bucket, wk, "aad"); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("Decrypt after DeleteKey: err = %v, want ErrKeyNotFound", err)
	}
	if got, err := decrypt(t, f.b, "other", otherWK, "aad"); err != nil || string(got) != "p" {
		t.Errorf("another key after DeleteKey: %q, %v", got, err)
	}

	// crypto-shredding: a new key under the same name does not bring the
	// old data back
	if err := f.b.CreateKey(ctx, mountID, bucket); err != nil {
		t.Fatal(err)
	}
	if _, err := decrypt(t, f.b, bucket, wk, "aad"); !errors.Is(err, transhim.ErrCiphertextMismatch) {
		t.Errorf("Decrypt of old data with a new key: err = %v, want ErrCiphertextMismatch", err)
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestDeleteKeyOnAnotherInstance: instances sharing a store keep a deleted key
// until their cache entry expires.
func TestDeleteKeyOnAnotherInstance(t *testing.T) {
	f := newFixture(t, hierarchical.WithKeyCacheTTL(time.Minute))
	ctx := t.Context()
	clk := &clock{t: time.Unix(1700000000, 0)}
	other, err := hierarchical.New(f.root, rootKey, f.store, hierarchical.WithKeyCacheTTL(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	hierarchical.SetNow(f.b, clk.now)
	hierarchical.SetNow(other, clk.now)

	if err := f.b.CreateKey(ctx, mountID, bucket); err != nil {
		t.Fatal(err)
	}
	wk := encrypt(t, f.b, bucket, "p", "aad")
	if _, err := decrypt(t, other, bucket, wk, "aad"); err != nil {
		t.Fatal(err)
	}

	if err := f.b.DeleteKey(ctx, mountID, bucket); err != nil {
		t.Fatal(err)
	}
	if _, err := decrypt(t, f.b, bucket, wk, "aad"); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("deleting instance: err = %v, want ErrKeyNotFound", err)
	}
	clk.advance(time.Minute - time.Nanosecond)
	if _, err := decrypt(t, other, bucket, wk, "aad"); err != nil {
		t.Errorf("other instance within the TTL: %v", err)
	}
	clk.advance(time.Nanosecond)
	if _, err := decrypt(t, other, bucket, wk, "aad"); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("other instance after the TTL: err = %v, want ErrKeyNotFound", err)
	}
}

func TestKeyCacheTTL(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		f := newFixture(t, hierarchical.WithKeyCacheTTL(time.Minute))
		clk := &clock{t: time.Unix(1700000000, 0)}
		hierarchical.SetNow(f.b, clk.now)
		for _, name := range []string{"a", "b"} {
			if err := f.b.CreateKey(t.Context(), mountID, name); err != nil {
				t.Fatal(err)
			}
		}
		wk := encrypt(t, f.b, "a", "p", "")
		clk.advance(59 * time.Second)
		decrypt(t, f.b, "a", wk, "")
		if _, d := f.rootCalls(); d != 0 {
			t.Errorf("root Decrypt called %d times within the TTL, want 0", d)
		}
		clk.advance(time.Second)
		if got, err := decrypt(t, f.b, "a", wk, ""); err != nil || string(got) != "p" {
			t.Errorf("Decrypt after expiry = %q, %v", got, err)
		}
		if _, d := f.rootCalls(); d != 1 {
			t.Errorf("root Decrypt called %d times after expiry, want 1", d)
		}
		// "b" was never used again: its key does not stay in memory forever
		if n := hierarchical.CacheLen(f.b); n != 1 {
			t.Errorf("%d keys cached, want 1", n)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		f := newFixture(t, hierarchical.WithKeyCacheTTL(0))
		if err := f.b.CreateKey(t.Context(), mountID, bucket); err != nil {
			t.Fatal(err)
		}
		wk := encrypt(t, f.b, bucket, "p", "")
		decrypt(t, f.b, bucket, wk, "")
		if _, d := f.rootCalls(); d != 2 || hierarchical.CacheLen(f.b) != 0 {
			t.Errorf("root Decrypt called %d times, %d keys cached; want 2, 0", d, hierarchical.CacheLen(f.b))
		}
	})
}

// slowStore delays Get until released, to hold a key load in flight.
type slowStore struct {
	*memstore.Store
	entered chan struct{}
	release chan struct{}
}

func (s *slowStore) Get(ctx context.Context, mountID, keyName string) (hierarchical.StoredKey, error) {
	k, err := s.Store.Get(ctx, mountID, keyName)
	if s.entered != nil {
		s.entered <- struct{}{}
		<-s.release
	}
	return k, err
}

// TestDeleteDuringLoad: a key that is being loaded while it is deleted must
// not end up in the cache.
func TestDeleteDuringLoad(t *testing.T) {
	ctx := t.Context()
	fb := transhimtest.NewFakeBackend()
	fb.AddKey(mountID, rootKey)
	store := &slowStore{Store: memstore.New()}
	creator, _ := hierarchical.New(fb, rootKey, store)
	if err := creator.CreateKey(ctx, mountID, bucket); err != nil {
		t.Fatal(err)
	}
	wk := encrypt(t, creator, bucket, "p", "")

	b, err := hierarchical.New(fb, rootKey, store)
	if err != nil {
		t.Fatal(err)
	}
	store.entered, store.release = make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := b.Decrypt(ctx, transhim.DecryptRequest{MountID: mountID, KeyName: bucket, Wrapped: wk})
		done <- err
	}()
	<-store.entered // the decrypt has read the key from the store
	store.entered = nil
	if err := b.DeleteKey(ctx, mountID, bucket); err != nil {
		t.Fatal(err)
	}
	close(store.release)
	if err := <-done; err != nil {
		t.Fatalf("the decrypt in flight: %v", err) // it may still succeed
	}
	if n := hierarchical.CacheLen(b); n != 0 {
		t.Fatalf("the deleted key is cached (%d entries)", n)
	}
	if _, err := decrypt(t, b, bucket, wk, ""); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("Decrypt after DeleteKey: err = %v, want ErrKeyNotFound", err)
	}
}

// TestStoredKeyIsBoundToItsName: a stored key copied to another name or mount
// must not unwrap, and the failure must not look like the client's fault.
func TestStoredKeyIsBoundToItsName(t *testing.T) {
	f := newFixture(t, hierarchical.WithKeyCacheTTL(0))
	ctx := t.Context()
	if err := f.b.CreateKey(ctx, mountID, "victim"); err != nil {
		t.Fatal(err)
	}
	stored, _ := f.store.Get(ctx, mountID, "victim")
	f.store.PutIfAbsent(ctx, mountID, "attacker", stored)
	f.store.PutIfAbsent(ctx, "other-mount", "victim", stored)

	_, err := f.b.Encrypt(ctx, transhim.EncryptRequest{MountID: mountID, KeyName: "attacker"})
	checkInternal(t, "copied to another name", err)
	_, err = f.b.Encrypt(ctx, transhim.EncryptRequest{MountID: "other-mount", KeyName: "victim"})
	checkInternal(t, "copied to another mount", err)
}

// checkInternal checks that err is none of the errors a server would blame on
// the client or report as a KMS outage.
func checkInternal(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: no error", name)
		return
	}
	for _, sentinel := range []error{transhim.ErrCiphertextMismatch, transhim.ErrKeyNotFound, transhim.ErrInvalidRequest, transhim.ErrUpstream, transhim.ErrPermissionDenied} {
		if errors.Is(err, sentinel) {
			t.Errorf("%s: err = %v, must not be %v", name, err, sentinel)
		}
	}
}

func TestRootErrors(t *testing.T) {
	ctx := t.Context()
	throttled := &transhim.UpstreamError{Err: errors.New("throttled"), Retryable: true}

	t.Run("create", func(t *testing.T) {
		f := newFixture(t)
		f.root.SetError(transhimtest.OpEncrypt, throttled)
		err := f.b.CreateKey(ctx, mountID, bucket)
		if ue, ok := errors.AsType[*transhim.UpstreamError](err); !ok || !ue.Retryable {
			t.Errorf("err = %v, want the root's retryable UpstreamError", err)
		}
		if f.store.Len() != 0 {
			t.Error("a key was stored although wrapping failed")
		}
		// a missing root key is a configuration error, not a missing bucket key
		f.root.SetError(transhimtest.OpEncrypt, transhim.ErrKeyNotFound)
		checkInternal(t, "missing root key", f.b.CreateKey(ctx, mountID, bucket))
	})
	t.Run("use", func(t *testing.T) {
		f := newFixture(t, hierarchical.WithKeyCacheTTL(0))
		if err := f.b.CreateKey(ctx, mountID, bucket); err != nil {
			t.Fatal(err)
		}
		wk := encrypt(t, f.b, bucket, "p", "")
		f.root.SetError(transhimtest.OpDecrypt, throttled)
		if _, err := decrypt(t, f.b, bucket, wk, ""); !errors.Is(err, transhim.ErrUpstream) {
			t.Errorf("err = %v, want ErrUpstream", err)
		}
		f.root.SetError(transhimtest.OpDecrypt, transhim.ErrPermissionDenied)
		if _, err := decrypt(t, f.b, bucket, wk, ""); !errors.Is(err, transhim.ErrPermissionDenied) {
			t.Errorf("err = %v, want ErrPermissionDenied", err)
		}
		f.root.SetError(transhimtest.OpDecrypt, transhim.ErrCiphertextMismatch)
		_, err := decrypt(t, f.b, bucket, wk, "")
		checkInternal(t, "root mismatch", err)
		// failures are not remembered
		f.root.SetError(transhimtest.OpDecrypt, nil)
		if got, err := decrypt(t, f.b, bucket, wk, ""); err != nil || string(got) != "p" {
			t.Errorf("Decrypt after the root recovered = %q, %v", got, err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		f := newFixture(t)
		f.root.SetDelay(time.Minute)
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		if err := f.b.CreateKey(ctx, mountID, bucket); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})
}

// failingStore fails every operation.
type failingStore struct{ err error }

func (s failingStore) Get(context.Context, string, string) (hierarchical.StoredKey, error) {
	return hierarchical.StoredKey{}, s.err
}
func (s failingStore) PutIfAbsent(context.Context, string, string, hierarchical.StoredKey) error {
	return s.err
}
func (s failingStore) Delete(context.Context, string, string) error { return s.err }

// putFailingStore has no keys and cannot store any.
type putFailingStore struct {
	*memstore.Store
	err error
}

func (s putFailingStore) PutIfAbsent(context.Context, string, string, hierarchical.StoredKey) error {
	return s.err
}

func TestStoreErrors(t *testing.T) {
	ctx := t.Context()
	fb := transhimtest.NewFakeBackend()
	fb.AddKey(mountID, rootKey)
	down := &transhim.UpstreamError{Err: errors.New("database is down")}

	b, err := hierarchical.New(fb, rootKey, failingStore{down})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.CreateKey(ctx, mountID, bucket); !errors.Is(err, transhim.ErrUpstream) {
		t.Errorf("CreateKey: err = %v, want the store's error", err)
	}
	if _, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: mountID, KeyName: bucket}); !errors.Is(err, transhim.ErrUpstream) {
		t.Errorf("Encrypt: err = %v, want the store's error", err)
	}
	if err := b.DeleteKey(ctx, mountID, bucket); !errors.Is(err, transhim.ErrUpstream) {
		t.Errorf("DeleteKey: err = %v, want the store's error", err)
	}
	if n := fb.Calls(transhimtest.OpEncrypt); n != 0 {
		t.Errorf("root Encrypt called %d times although the store is down", n)
	}

	b, err = hierarchical.New(fb, rootKey, putFailingStore{memstore.New(), down})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.CreateKey(ctx, mountID, bucket); !errors.Is(err, transhim.ErrUpstream) {
		t.Errorf("CreateKey with a failing PutIfAbsent: err = %v, want the store's error", err)
	}
	// the key that could not be stored must not be usable from memory
	if _, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: mountID, KeyName: bucket}); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("Encrypt after a failed create: err = %v, want ErrKeyNotFound", err)
	}
}

// TestDeleteForgetsKeyEvenIfStoreFails: the store may have deleted the key
// although it reported a failure.
func TestDeleteForgetsKeyEvenIfStoreFails(t *testing.T) {
	ctx := t.Context()
	fb := transhimtest.NewFakeBackend()
	fb.AddKey(mountID, rootKey)
	store := &deleteFailingStore{Store: memstore.New()}
	b, _ := hierarchical.New(fb, rootKey, store)
	if err := b.CreateKey(ctx, mountID, bucket); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteKey(ctx, mountID, bucket); err == nil {
		t.Fatal("DeleteKey succeeded")
	}
	if n := hierarchical.CacheLen(b); n != 0 {
		t.Errorf("%d keys cached after a failed delete, want 0", n)
	}
}

type deleteFailingStore struct{ *memstore.Store }

func (s *deleteFailingStore) Delete(ctx context.Context, mountID, keyName string) error {
	s.Store.Delete(ctx, mountID, keyName)
	return errors.New("connection lost")
}

func TestNewErrors(t *testing.T) {
	fb := transhimtest.NewFakeBackend()
	store := memstore.New()
	if _, err := hierarchical.New(nil, rootKey, store); err == nil {
		t.Error("New accepted a nil root backend")
	}
	if _, err := hierarchical.New(fb, "", store); err == nil {
		t.Error("New accepted an empty root key name")
	}
	if _, err := hierarchical.New(fb, rootKey, nil); err == nil {
		t.Error("New accepted a nil store")
	}
	if _, err := hierarchical.New(fb, rootKey, store, hierarchical.WithKeyCacheTTL(-time.Second)); err == nil {
		t.Error("New accepted a negative TTL")
	}
}

func TestConcurrentUse(t *testing.T) {
	f := newFixture(t, hierarchical.WithKeyCacheTTL(time.Millisecond))
	ctx := t.Context()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			name := "bucket" + string(rune('0'+g%3))
			for range 100 {
				if err := f.b.CreateKey(ctx, mountID, name); err != nil {
					t.Errorf("CreateKey: %v", err)
				}
				wk, err := f.b.Encrypt(ctx, transhim.EncryptRequest{MountID: mountID, KeyName: name, Plaintext: []byte("p")})
				if err != nil {
					continue // another goroutine deleted the key
				}
				got, err := f.b.Decrypt(ctx, transhim.DecryptRequest{MountID: mountID, KeyName: name, Wrapped: wk})
				if err == nil && string(got) != "p" {
					t.Errorf("Decrypt = %q", got)
				}
				if g == 0 {
					f.b.DeleteKey(ctx, mountID, name)
				}
			}
		})
	}
	wg.Wait()
}

// TestBehindServer runs RGW's SSE-S3 request sequence (docs/compat.md) against
// a server with a hierarchical mount.
func TestBehindServer(t *testing.T) {
	f := newFixture(t)
	srv, err := transhim.NewServer(
		transhim.Mount("/v1/transit-sse-s3", mountID, f.b),
		transhim.WithAuthorizer(transhim.StaticTokenAuthorizer("token")),
		transhim.WithDecryptCache(transhim.DecryptCacheConfig{MaxEntries: 100, TTL: time.Hour}),
		transhim.WithLogger(slog.New(slog.DiscardHandler)),
	)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	call := func(method, path string, body map[string]any) (int, map[string]any) {
		t.Helper()
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, ts.URL+"/v1/transit-sse-s3/"+path, r)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Vault-Token", "token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		var out struct {
			Data   map[string]any `json:"data"`
			Errors []string       `json:"errors"`
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("%s %s: %q", method, path, raw)
			}
		}
		if len(out.Errors) > 0 {
			return res.StatusCode, map[string]any{"error": out.Errors[0]}
		}
		return res.StatusCode, out.Data
	}
	rgwContext := base64.StdEncoding.EncodeToString([]byte(`{"aws:s3:arn":"arn:aws:s3::owner:bucket/object"}`))
	ctxBody := map[string]any{"context": rgwContext}

	if status, data := call("POST", "datakey/plaintext/"+bucket, ctxBody); status != 400 || data["error"] != "encryption key not found" {
		t.Errorf("datakey before create: %d %v", status, data)
	}
	if status, _ := call("POST", "keys/"+bucket, map[string]any{"type": "chacha20-poly1305", "derived": true}); status != 204 {
		t.Fatalf("create: %d", status)
	}
	status, dk := call("POST", "datakey/plaintext/"+bucket, ctxBody)
	if status != 200 {
		t.Fatalf("datakey: %d %v", status, dk)
	}
	if ct, _ := dk["ciphertext"].(string); !strings.HasPrefix(ct, "vault:v1:") {
		t.Errorf("ciphertext = %q", ct)
	}
	decBody := map[string]any{"context": rgwContext, "ciphertext": dk["ciphertext"]}
	for range 3 {
		if status, dec := call("POST", "decrypt/"+bucket, decBody); status != 200 || dec["plaintext"] != dk["plaintext"] {
			t.Fatalf("decrypt: %d %v", status, dec)
		}
	}
	if status, dec := call("POST", "decrypt/"+bucket, map[string]any{"ciphertext": dk["ciphertext"]}); status != 400 || dec["error"] != "invalid ciphertext" {
		t.Errorf("decrypt without context: %d %v", status, dec)
	}
	// create again (after DeleteBucketEncryption): the key survives
	call("POST", "keys/"+bucket, nil)
	if e, d := f.rootCalls(); e != 1 || d != 0 {
		t.Errorf("root calls = %d encrypts, %d decrypts; want 1, 0", e, d)
	}

	// DeleteBucket
	if status, _ := call("POST", "keys/"+bucket+"/config", map[string]any{"deletion_allowed": true}); status != 204 {
		t.Errorf("config: %d", status)
	}
	if status, _ := call("DELETE", "keys/"+bucket, nil); status != 204 {
		t.Errorf("delete: %d", status)
	}
	if f.store.Len() != 0 {
		t.Error("the intermediate key is still in the store")
	}
	// gone at once, although the plaintext was in the decrypt cache
	if status, dec := call("POST", "decrypt/"+bucket, decBody); status != 400 || dec["error"] != "encryption key not found" {
		t.Errorf("decrypt after delete: %d %v", status, dec)
	}
}

// TestConcurrentLoadsAreMerged: with a slow KMS as root, requests for a key
// that is not in memory must share one load.
func TestConcurrentLoadsAreMerged(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	for _, name := range []string{"a", "b"} {
		if err := f.b.CreateKey(ctx, mountID, name); err != nil {
			t.Fatal(err)
		}
	}
	wk := encrypt(t, f.b, "a", "p", "")

	// a second instance has nothing in memory, like after a restart
	cold, err := hierarchical.New(f.root, rootKey, f.store)
	if err != nil {
		t.Fatal(err)
	}
	f.root.SetDelay(200 * time.Millisecond)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if got, err := decrypt(t, cold, "a", wk, ""); err != nil || string(got) != "p" {
				t.Errorf("Decrypt = %q, %v", got, err)
			}
		})
	}
	// another key is another load
	wg.Go(func() { encrypt(t, cold, "b", "p", "") })
	wg.Wait()
	if _, d := f.rootCalls(); d != 2 {
		t.Errorf("root Decrypt called %d times, want 2 (one per key)", d)
	}

	t.Run("failures are shared but not kept", func(t *testing.T) {
		cold, _ := hierarchical.New(f.root, rootKey, f.store)
		f.root.SetError(transhimtest.OpDecrypt, transhim.ErrUpstream)
		_, before := f.rootCalls()
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if _, err := decrypt(t, cold, "a", wk, ""); !errors.Is(err, transhim.ErrUpstream) {
					t.Errorf("err = %v, want ErrUpstream", err)
				}
			})
		}
		wg.Wait()
		if _, d := f.rootCalls(); d-before != 1 {
			t.Errorf("root Decrypt called %d times, want 1", d-before)
		}
		f.root.SetError(transhimtest.OpDecrypt, nil)
		if _, err := decrypt(t, cold, "a", wk, ""); err != nil {
			t.Errorf("Decrypt after the root recovered: %v", err)
		}
	})
}

// TestLoadSurvivesCanceledRequest: when the request that started a load goes
// away, the requests waiting for the same key must still get it.
func TestLoadSurvivesCanceledRequest(t *testing.T) {
	f := newFixture(t)
	if err := f.b.CreateKey(t.Context(), mountID, bucket); err != nil {
		t.Fatal(err)
	}
	wk := encrypt(t, f.b, bucket, "p", "")
	cold, _ := hierarchical.New(f.root, rootKey, f.store)
	f.root.SetDelay(200 * time.Millisecond)

	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() {
		cold.Decrypt(ctx, transhim.DecryptRequest{MountID: mountID, KeyName: bucket, Wrapped: wk})
	})
	for _, d := f.rootCalls(); d == 0; _, d = f.rootCalls() {
		time.Sleep(time.Millisecond)
	}
	wg.Go(func() {
		if got, err := decrypt(t, cold, bucket, wk, ""); err != nil || string(got) != "p" {
			t.Errorf("waiting request: %q, %v", got, err)
		}
	})
	time.Sleep(20 * time.Millisecond) // let the second request join
	cancel()
	wg.Wait()
	if _, d := f.rootCalls(); d != 1 {
		t.Errorf("root Decrypt called %d times, want 1", d)
	}
}
