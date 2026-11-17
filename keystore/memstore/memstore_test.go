package memstore_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/hierarchical"
	"github.com/fujiwara/transhim/keystore/memstore"
)

func storedKey(blob string) hierarchical.StoredKey {
	return hierarchical.StoredKey{
		Wrapped:   transhim.WrappedKey{KeyRef: "ref", Version: 2, Blob: []byte(blob)},
		CreatedAt: time.Unix(1700000000, 0),
	}
}

func TestStore(t *testing.T) {
	ctx := t.Context()
	s := memstore.New()

	if _, err := s.Get(ctx, "m", "k"); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("Get on an empty store: err = %v, want ErrKeyNotFound", err)
	}
	in := storedKey("first")
	if err := s.PutIfAbsent(ctx, "m", "k", in); err != nil {
		t.Fatal(err)
	}
	in.Wrapped.Blob[0] = 'X' // the store must hold its own copy

	got, err := s.Get(ctx, "m", "k")
	if err != nil {
		t.Fatal(err)
	}
	if got.Wrapped.KeyRef != "ref" || got.Wrapped.Version != 2 || string(got.Wrapped.Blob) != "first" || !got.CreatedAt.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("Get = %+v", got)
	}
	got.Wrapped.Blob[0] = 'Y' // and hand out copies
	if again, _ := s.Get(ctx, "m", "k"); string(again.Wrapped.Blob) != "first" {
		t.Errorf("stored key was modified through a returned value: %q", again.Wrapped.Blob)
	}

	// an existing key is never replaced
	if err := s.PutIfAbsent(ctx, "m", "k", storedKey("second")); !errors.Is(err, hierarchical.ErrKeyExists) {
		t.Errorf("second PutIfAbsent: err = %v, want ErrKeyExists", err)
	}
	if got, _ := s.Get(ctx, "m", "k"); string(got.Wrapped.Blob) != "first" {
		t.Errorf("stored key was replaced: %q", got.Wrapped.Blob)
	}

	// keys are per mount ID
	if _, err := s.Get(ctx, "m2", "k"); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("Get in another mount: err = %v, want ErrKeyNotFound", err)
	}
	if err := s.PutIfAbsent(ctx, "m2", "k", storedKey("other mount")); err != nil {
		t.Errorf("PutIfAbsent in another mount: %v", err)
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2", s.Len())
	}

	// Delete is idempotent and only removes its key
	for range 2 {
		if err := s.Delete(ctx, "m", "k"); err != nil {
			t.Errorf("Delete: %v", err)
		}
	}
	if _, err := s.Get(ctx, "m", "k"); !errors.Is(err, transhim.ErrKeyNotFound) {
		t.Errorf("Get after Delete: err = %v, want ErrKeyNotFound", err)
	}
	if got, err := s.Get(ctx, "m2", "k"); err != nil || string(got.Wrapped.Blob) != "other mount" {
		t.Errorf("key of another mount: %+v, %v", got, err)
	}
	if err := s.PutIfAbsent(ctx, "m", "k", storedKey("after delete")); err != nil {
		t.Errorf("PutIfAbsent after Delete: %v", err)
	}
}

func TestPutIfAbsentIsAtomic(t *testing.T) {
	ctx := t.Context()
	s := memstore.New()
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			err := s.PutIfAbsent(ctx, "m", "k", storedKey(string(rune('a'+i))))
			switch {
			case err == nil:
				won.Add(1)
			case !errors.Is(err, hierarchical.ErrKeyExists):
				t.Errorf("PutIfAbsent: %v", err)
			}
		})
	}
	wg.Wait()
	if won.Load() != 1 || s.Len() != 1 {
		t.Errorf("%d calls succeeded, %d keys stored; want 1 and 1", won.Load(), s.Len())
	}
}
