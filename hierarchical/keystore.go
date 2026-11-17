package hierarchical

import (
	"context"
	"errors"
	"time"

	"github.com/fujiwara/transhim"
)

// ErrKeyExists is returned by KeyStore.PutIfAbsent when a key is already
// stored under the given mount ID and key name.
var ErrKeyExists = errors.New("key already exists")

// KeyStore persists the wrapped intermediate keys. It is the only state of a
// hierarchical Backend, and it is as important as the data it protects: a lost
// entry makes everything encrypted with that key unreadable.
//
// The stored keys are wrapped by the root key, so the store does not have to
// be secret. It must be durable and consistent.
//
// Implementations must be safe for concurrent use, also by several processes
// if several server instances share the store.
type KeyStore interface {
	// Get returns the key stored for (mountID, keyName). If there is none, it
	// returns an error wrapping transhim.ErrKeyNotFound.
	Get(ctx context.Context, mountID, keyName string) (StoredKey, error)
	// PutIfAbsent stores k for (mountID, keyName) unless a key is already
	// stored there. In that case it must leave the stored key untouched and
	// return an error wrapping ErrKeyExists. The check and the write must be
	// atomic: of several concurrent calls for the same key, exactly one may
	// succeed.
	PutIfAbsent(ctx context.Context, mountID, keyName string, k StoredKey) error
	// Delete removes the key stored for (mountID, keyName). A missing key is
	// not an error.
	Delete(ctx context.Context, mountID, keyName string) error
}

// StoredKey is an intermediate key as kept in a KeyStore.
type StoredKey struct {
	// Wrapped is the intermediate key, wrapped by the root backend. All of
	// its fields must be stored and returned unchanged.
	Wrapped transhim.WrappedKey
	// CreatedAt is when the key was created.
	CreatedAt time.Time
}
