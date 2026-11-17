// Package memstore provides an in-memory hierarchical.KeyStore.
//
// It is for tests and development only. Its keys are gone when the process
// ends, and with them everything that was encrypted with them.
package memstore

import (
	"context"
	"fmt"
	"sync"

	"github.com/fujiwara/transhim"
	"github.com/fujiwara/transhim/hierarchical"
)

type keyID struct{ mountID, name string }

// Store is an in-memory hierarchical.KeyStore. It is safe for concurrent use.
type Store struct {
	mu   sync.Mutex
	keys map[keyID]hierarchical.StoredKey
}

var _ hierarchical.KeyStore = (*Store)(nil)

// New returns an empty Store.
func New() *Store {
	return &Store{keys: map[keyID]hierarchical.StoredKey{}}
}

func clone(k hierarchical.StoredKey) hierarchical.StoredKey {
	k.Wrapped.Blob = append([]byte(nil), k.Wrapped.Blob...)
	return k
}

// Get implements hierarchical.KeyStore.
func (s *Store) Get(_ context.Context, mountID, keyName string) (hierarchical.StoredKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID{mountID, keyName}]
	if !ok {
		return hierarchical.StoredKey{}, fmt.Errorf("%w: %s", transhim.ErrKeyNotFound, keyName)
	}
	return clone(k), nil
}

// PutIfAbsent implements hierarchical.KeyStore.
func (s *Store) PutIfAbsent(_ context.Context, mountID, keyName string, k hierarchical.StoredKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := keyID{mountID, keyName}
	if _, ok := s.keys[id]; ok {
		return fmt.Errorf("%w: %s", hierarchical.ErrKeyExists, keyName)
	}
	s.keys[id] = clone(k)
	return nil
}

// Delete implements hierarchical.KeyStore.
func (s *Store) Delete(_ context.Context, mountID, keyName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, keyID{mountID, keyName})
	return nil
}

// Len returns the number of stored keys.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}
