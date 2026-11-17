package transhimtest_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/hierarchical"
	"github.com/fujiwara/transhim/keystore/memstore"
	"github.com/fujiwara/transhim/transhimtest"
)

func TestKeyStoreConformance(t *testing.T) {
	store := memstore.New()
	// keys of someone else must be left alone
	store.PutIfAbsent(t.Context(), "other", "key", hierarchical.StoredKey{Wrapped: transhim.WrappedKey{Version: 1, Blob: []byte("x")}})
	t.Run("memstore", func(t *testing.T) {
		transhimtest.RunKeyStoreConformance(t, store)
	})
	if n := store.Len(); n != 1 {
		t.Errorf("%d keys in the store after the suite, want the 1 that was there before", n)
	}
}

// TestKeyStoreConformanceDetectsViolations makes sure the suite is not
// vacuous: a store that breaks the contract must fail it.
func TestKeyStoreConformanceDetectsViolations(t *testing.T) {
	for name, store := range map[string]hierarchical.KeyStore{
		"put replaces":               replacingStore{memstore.New()},
		"put reports no conflict":    silentStore{memstore.New()},
		"missing key is unspecific":  vagueStore{memstore.New()},
		"delete of a missing key":    strictDeleteStore{memstore.New()},
		"names are case-insensitive": foldingStore{memstore.New()},
		"mount ID is ignored":        mountlessStore{memstore.New()},
		"blob is truncated at NUL":   textStore{memstore.New()},
		"key ref is dropped":         refDroppingStore{memstore.New()},
	} {
		t.Run(name, func(t *testing.T) {
			if !fails(func(t *testing.T) { transhimtest.RunKeyStoreConformance(t, store) }) {
				t.Error("the conformance suite passed a broken store")
			}
		})
	}
}

// replacingStore overwrites existing keys.
type replacingStore struct{ *memstore.Store }

func (s replacingStore) PutIfAbsent(ctx context.Context, mountID, keyName string, k hierarchical.StoredKey) error {
	s.Delete(ctx, mountID, keyName)
	return s.Store.PutIfAbsent(ctx, mountID, keyName, k)
}

// silentStore keeps the existing key but does not say so.
type silentStore struct{ *memstore.Store }

func (s silentStore) PutIfAbsent(ctx context.Context, mountID, keyName string, k hierarchical.StoredKey) error {
	s.Store.PutIfAbsent(ctx, mountID, keyName, k)
	return nil
}

// vagueStore reports a missing key with an error of its own.
type vagueStore struct{ *memstore.Store }

func (s vagueStore) Get(ctx context.Context, mountID, keyName string) (hierarchical.StoredKey, error) {
	k, err := s.Store.Get(ctx, mountID, keyName)
	if err != nil {
		return k, errors.New("no rows")
	}
	return k, nil
}

// strictDeleteStore fails when asked to delete a key it does not have.
type strictDeleteStore struct{ *memstore.Store }

func (s strictDeleteStore) Delete(ctx context.Context, mountID, keyName string) error {
	if _, err := s.Get(ctx, mountID, keyName); err != nil {
		return err
	}
	return s.Store.Delete(ctx, mountID, keyName)
}

// foldingStore compares key names without regard to case, like a database
// column with a case-insensitive collation.
type foldingStore struct{ *memstore.Store }

func (s foldingStore) Get(ctx context.Context, mountID, keyName string) (hierarchical.StoredKey, error) {
	return s.Store.Get(ctx, mountID, strings.ToLower(keyName))
}

func (s foldingStore) PutIfAbsent(ctx context.Context, mountID, keyName string, k hierarchical.StoredKey) error {
	return s.Store.PutIfAbsent(ctx, mountID, strings.ToLower(keyName), k)
}

func (s foldingStore) Delete(ctx context.Context, mountID, keyName string) error {
	return s.Store.Delete(ctx, mountID, strings.ToLower(keyName))
}

// mountlessStore keys by name only.
type mountlessStore struct{ *memstore.Store }

func (s mountlessStore) Get(ctx context.Context, _, keyName string) (hierarchical.StoredKey, error) {
	return s.Store.Get(ctx, "", keyName)
}

func (s mountlessStore) PutIfAbsent(ctx context.Context, _, keyName string, k hierarchical.StoredKey) error {
	return s.Store.PutIfAbsent(ctx, "", keyName, k)
}

func (s mountlessStore) Delete(ctx context.Context, _, keyName string) error {
	return s.Store.Delete(ctx, "", keyName)
}

// textStore treats the blob as a C string.
type textStore struct{ *memstore.Store }

func (s textStore) PutIfAbsent(ctx context.Context, mountID, keyName string, k hierarchical.StoredKey) error {
	if i := strings.IndexByte(string(k.Wrapped.Blob), 0); i >= 0 {
		k.Wrapped.Blob = k.Wrapped.Blob[:i]
	}
	return s.Store.PutIfAbsent(ctx, mountID, keyName, k)
}

// refDroppingStore stores the blob only.
type refDroppingStore struct{ *memstore.Store }

func (s refDroppingStore) PutIfAbsent(ctx context.Context, mountID, keyName string, k hierarchical.StoredKey) error {
	k.Wrapped.KeyRef = ""
	return s.Store.PutIfAbsent(ctx, mountID, keyName, k)
}
