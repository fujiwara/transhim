package transhimtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/hierarchical"
)

// RunKeyStoreConformance checks that store keeps the contract of
// hierarchical.KeyStore. Use it to test a KeyStore of your own:
//
//	func TestMyStore(t *testing.T) {
//		transhimtest.RunKeyStoreConformance(t, mystore.New(db))
//	}
//
// The store may be shared and may hold other keys: the suite works under mount
// IDs of its own (they start with "transhimtest-") and deletes what it stored.
//
// What it cannot check is durability: that keys survive a restart and a
// failure of the store. Test that separately; losing a key loses everything
// encrypted with it.
func RunKeyStoreConformance(t *testing.T, store hierarchical.KeyStore) {
	t.Helper()
	suffix := make([]byte, 6)
	rand.Read(suffix)
	k := &keyStoreSuite{
		store: store,
		mount: fmt.Sprintf("transhimtest-%x", suffix),
	}
	// Leave nothing behind. The test's context is canceled by then.
	t.Cleanup(func() {
		for _, id := range k.stored() {
			if err := store.Delete(context.Background(), id[0], id[1]); err != nil {
				t.Errorf("cleanup: Delete(%q, %q): %v", id[0], id[1], err)
			}
		}
	})

	t.Run("get a missing key", func(t *testing.T) {
		_, err := store.Get(t.Context(), k.mount, "missing")
		if !errors.Is(err, transhim.ErrKeyNotFound) {
			t.Errorf("Get of a missing key: err = %v, want an error wrapping transhim.ErrKeyNotFound", err)
		}
	})

	t.Run("put and get", func(t *testing.T) {
		// everything in a StoredKey must come back as it went in
		in := hierarchical.StoredKey{
			Wrapped: transhim.WrappedKey{
				KeyRef:  "arn:aws:kms:ap-northeast-1:123456789012:key/11111111-2222-3333-4444-555555555555",
				Version: 7,
				Blob:    allBytes(),
			},
			CreatedAt: time.Date(2026, 11, 17, 9, 30, 15, 123000000, time.UTC),
		}
		k.put(t, k.mount, "roundtrip", in)
		got := k.get(t, k.mount, "roundtrip")
		k.wantEqual(t, got, in)

		// the store must not share memory with its callers
		in.Wrapped.Blob[0] ^= 0xff
		if len(got.Wrapped.Blob) > 1 {
			got.Wrapped.Blob[1] ^= 0xff
		}
		again := k.get(t, k.mount, "roundtrip")
		if !bytes.Equal(again.Wrapped.Blob, allBytes()) {
			t.Error("the stored key changed when a value passed to or returned by the store was modified")
		}

		// an empty KeyRef and a short blob are valid too
		minimal := hierarchical.StoredKey{Wrapped: transhim.WrappedKey{Version: 1, Blob: []byte{0}}, CreatedAt: time.Unix(1, 0)}
		k.put(t, k.mount, "minimal", minimal)
		k.wantEqual(t, k.get(t, k.mount, "minimal"), minimal)
	})

	t.Run("put does not replace", func(t *testing.T) {
		first, second := testKey("first"), testKey("second")
		k.put(t, k.mount, "once", first)
		err := store.PutIfAbsent(t.Context(), k.mount, "once", second)
		if !errors.Is(err, hierarchical.ErrKeyExists) {
			t.Errorf("PutIfAbsent on an existing key: err = %v, want an error wrapping hierarchical.ErrKeyExists", err)
		}
		// Replacing a key makes everything encrypted with it unreadable.
		k.wantEqual(t, k.get(t, k.mount, "once"), first)
	})

	t.Run("keys are separate", func(t *testing.T) {
		other := k.mount + "-other"
		names := []string{
			"a", "A", "a ", "a.b_c-d", "tenant$bucket", "1434f035-2747-4d60-a14f-5a0efa651729.4126.2",
			"日本語", "with space", "per%cent", "under_score", "quote'quote", `back\slash`, `"; DROP TABLE keys; --`,
			string(bytes.Repeat([]byte("k"), 255)),
		}
		for i, name := range names {
			k.put(t, k.mount, name, testKey(fmt.Sprintf("%s/%d", k.mount, i)))
			k.put(t, other, name, testKey(fmt.Sprintf("%s/%d", other, i)))
		}
		for i, name := range names {
			k.wantEqual(t, k.get(t, k.mount, name), testKey(fmt.Sprintf("%s/%d", k.mount, i)))
			k.wantEqual(t, k.get(t, other, name), testKey(fmt.Sprintf("%s/%d", other, i)))
		}
		// names that only look alike to a pattern match or a case-insensitive
		// comparison are different keys
		for _, name := range []string{"per_cent", "PER%CENT", "under%score", "a  ", "b"} {
			if _, err := store.Get(t.Context(), k.mount, name); !errors.Is(err, transhim.ErrKeyNotFound) {
				t.Errorf("Get(%q): err = %v, want ErrKeyNotFound: it was never stored", name, err)
			}
		}
		// the mount ID and the key name must not run into each other
		k.put(t, k.mount+"x", "y", testKey("mount+x"))
		if _, err := store.Get(t.Context(), k.mount, "xy"); !errors.Is(err, transhim.ErrKeyNotFound) {
			t.Errorf("Get(%q, %q) found the key stored as (%q, %q)", k.mount, "xy", k.mount+"x", "y")
		}
	})

	t.Run("delete", func(t *testing.T) {
		ctx := t.Context()
		k.put(t, k.mount, "doomed", testKey("doomed"))
		k.put(t, k.mount, "survivor", testKey("survivor"))
		k.put(t, k.mount+"-other", "doomed", testKey("other mount"))

		// twice: deleting a key that is gone is not an error
		for range 2 {
			if err := store.Delete(ctx, k.mount, "doomed"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
		}
		if err := store.Delete(ctx, k.mount, "never-existed"); err != nil {
			t.Errorf("Delete of a key that never existed: %v", err)
		}
		if _, err := store.Get(ctx, k.mount, "doomed"); !errors.Is(err, transhim.ErrKeyNotFound) {
			t.Errorf("Get after Delete: err = %v, want ErrKeyNotFound", err)
		}
		k.wantEqual(t, k.get(t, k.mount, "survivor"), testKey("survivor"))
		k.wantEqual(t, k.get(t, k.mount+"-other", "doomed"), testKey("other mount"))

		// the name is free again
		k.put(t, k.mount, "doomed", testKey("reborn"))
		k.wantEqual(t, k.get(t, k.mount, "doomed"), testKey("reborn"))
	})

	t.Run("concurrent put", func(t *testing.T) {
		// Several server instances may create the same bucket key at once.
		// Exactly one must win, and all must then read the winner's key.
		const n = 16
		var won atomic.Int32
		winner := make(chan int, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				err := store.PutIfAbsent(t.Context(), k.mount, "race", testKey(fmt.Sprintf("racer-%d", i)))
				k.track(k.mount, "race")
				switch {
				case err == nil:
					won.Add(1)
					winner <- i
				case !errors.Is(err, hierarchical.ErrKeyExists):
					t.Errorf("PutIfAbsent: err = %v, want nil or ErrKeyExists", err)
				}
			})
		}
		wg.Wait()
		if won.Load() != 1 {
			t.Fatalf("%d of %d concurrent PutIfAbsent calls succeeded, want exactly 1", won.Load(), n)
		}
		k.wantEqual(t, k.get(t, k.mount, "race"), testKey(fmt.Sprintf("racer-%d", <-winner)))
	})

	t.Run("behind the hierarchical backend", func(t *testing.T) {
		ctx := t.Context()
		root := NewFakeBackend()
		root.AddKey(k.mount, "root")
		b, err := hierarchical.New(root, "root", store)
		if err != nil {
			t.Fatal(err)
		}
		const name = "bucket"
		if err := b.CreateKey(ctx, k.mount, name); err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		k.track(k.mount, name)
		wk, err := b.Encrypt(ctx, transhim.EncryptRequest{MountID: k.mount, KeyName: name, Plaintext: []byte("data key"), AAD: []byte("aad")})
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		// another instance, as after a restart, reads the key from the store
		other, err := hierarchical.New(root, "root", store)
		if err != nil {
			t.Fatal(err)
		}
		got, err := other.Decrypt(ctx, transhim.DecryptRequest{MountID: k.mount, KeyName: name, Wrapped: wk, AAD: []byte("aad")})
		if err != nil || string(got) != "data key" {
			t.Errorf("Decrypt on another instance = %q, %v", got, err)
		}
		if err := other.DeleteKey(ctx, k.mount, name); err != nil {
			t.Fatalf("DeleteKey: %v", err)
		}
		if _, err := other.Decrypt(ctx, transhim.DecryptRequest{MountID: k.mount, KeyName: name, Wrapped: wk, AAD: []byte("aad")}); !errors.Is(err, transhim.ErrKeyNotFound) {
			t.Errorf("Decrypt after DeleteKey: err = %v, want ErrKeyNotFound", err)
		}
	})

}

type keyStoreSuite struct {
	store hierarchical.KeyStore
	mount string

	mu   sync.Mutex
	keys [][2]string
}

// track remembers a key for cleanup.
func (k *keyStoreSuite) track(mountID, name string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys = append(k.keys, [2]string{mountID, name})
}

func (k *keyStoreSuite) stored() [][2]string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.keys
}

func (k *keyStoreSuite) put(t *testing.T, mountID, name string, key hierarchical.StoredKey) {
	t.Helper()
	k.track(mountID, name)
	if err := k.store.PutIfAbsent(t.Context(), mountID, name, key); err != nil {
		t.Fatalf("PutIfAbsent(%q, %q): %v", mountID, name, err)
	}
}

func (k *keyStoreSuite) get(t *testing.T, mountID, name string) hierarchical.StoredKey {
	t.Helper()
	key, err := k.store.Get(t.Context(), mountID, name)
	if err != nil {
		t.Fatalf("Get(%q, %q): %v", mountID, name, err)
	}
	return key
}

// wantEqual compares two stored keys. CreatedAt is compared as an instant, to
// the millisecond: a store may keep less precision and another time zone.
func (k *keyStoreSuite) wantEqual(t *testing.T, got, want hierarchical.StoredKey) {
	t.Helper()
	if got.Wrapped.KeyRef != want.Wrapped.KeyRef || got.Wrapped.Version != want.Wrapped.Version {
		t.Errorf("stored key has KeyRef %q and Version %d, want %q and %d",
			got.Wrapped.KeyRef, got.Wrapped.Version, want.Wrapped.KeyRef, want.Wrapped.Version)
	}
	if !bytes.Equal(got.Wrapped.Blob, want.Wrapped.Blob) {
		t.Errorf("stored key has a blob of %d bytes that differs from the %d bytes stored", len(got.Wrapped.Blob), len(want.Wrapped.Blob))
	}
	if !got.CreatedAt.Truncate(time.Millisecond).Equal(want.CreatedAt.Truncate(time.Millisecond)) {
		t.Errorf("stored key has CreatedAt %v, want %v", got.CreatedAt, want.CreatedAt)
	}
}

// testKey returns a stored key that can be told apart by its label.
func testKey(label string) hierarchical.StoredKey {
	return hierarchical.StoredKey{
		Wrapped:   transhim.WrappedKey{KeyRef: "ref-" + label, Version: 1, Blob: []byte("blob of " + label)},
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

// allBytes returns every byte value, twice: wrapped keys are binary.
func allBytes() []byte {
	b := make([]byte, 512)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}
