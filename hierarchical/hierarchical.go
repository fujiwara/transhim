// Package hierarchical provides a transhim.Backend that gives every key name
// its own key without creating a key in the KMS for each of them.
//
// One root key lives in the KMS, behind a root transhim.Backend. Every key
// name gets a random intermediate key, which is stored in a KeyStore wrapped
// by the root key. Data is encrypted locally with the intermediate key.
// Deleting a key deletes its intermediate key, which makes everything
// encrypted with it unreadable (crypto-shredding).
//
// It is made for Ceph RGW SSE-S3, where RGW creates one key per bucket and
// deletes it with the bucket.
//
// Things to know:
//
//   - The KeyStore is state that must not be lost. See KeyStore.
//   - The root key name, like the mount ID, is bound into the stored keys.
//     Changing either makes the stored keys unusable.
//   - Unwrapped intermediate keys are cached in memory (WithKeyCacheTTL).
//     Deleting a key drops it from the cache of the instance that handled the
//     deletion. Other instances sharing the KeyStore keep using it until
//     their cache entry expires, so the deletion is complete only after that
//     TTL (and after the TTL of the server's decrypt cache, if enabled).
//   - Loading a key (first use, or after its cache entry expired) costs one
//     KeyStore read and one root backend call. Requests for the same key that
//     arrive meanwhile wait for that load instead of starting their own.
//   - Data is encrypted with AES-256-GCM and a random 96-bit nonce, which is
//     sound for up to about 2^32 encryptions per key. A bucket key encrypts
//     one data key per object written, so this is far away; there is no key
//     rotation that would lift the limit.
//   - A key is not always deleted when its bucket is: see docs/compat.md.
//     Orphaned intermediate keys can stay behind in the KeyStore.
//   - With ReadOnly, the Backend never writes to the KeyStore, and may be
//     given read access only. Keys are then created and deleted by another
//     Backend on the same KeyStore, for example in a provisioning tool.
package hierarchical

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fujiwara/transhim"
	"golang.org/x/sync/singleflight"
)

const (
	// keyRef marks ciphertexts made by this backend: AES-256-GCM with the
	// intermediate key, Blob = nonce || ciphertext.
	keyRef = "h1"
	// rootAADPrefix differs from the prefix of the server's AAD, so that a
	// wrapped intermediate key can never pass as an ordinary ciphertext of
	// the root backend, or the other way round.
	rootAADPrefix = "transhim/hierarchical/v1"

	intermediateKeySize = 32

	// DefaultKeyCacheTTL is how long an unwrapped intermediate key is kept in
	// memory by default.
	DefaultKeyCacheTTL = 5 * time.Minute
)

// Option configures a Backend.
type Option func(*Backend) error

// WithKeyCacheTTL sets how long an unwrapped intermediate key is kept in
// memory before it is fetched from the KeyStore and unwrapped by the root
// backend again. The default is DefaultKeyCacheTTL. Zero disables the cache:
// every operation then calls the KeyStore and the root backend.
//
// With several instances sharing a KeyStore, this is how long a key deleted
// through one instance stays usable through the others.
func WithKeyCacheTTL(ttl time.Duration) Option {
	return func(b *Backend) error {
		if ttl < 0 {
			return errors.New("key cache TTL must not be negative")
		}
		b.ttl = ttl
		return nil
	}
}

// ReadOnly makes the Backend never write to the KeyStore, so that the server
// can run with read access to it only. Keys are created and deleted elsewhere:
// by a Backend without this option, with the same root key name, on the same
// KeyStore, calling CreateKey and DeleteKey under the same mount ID.
//
// What changes:
//
//   - CreateKey creates nothing. It succeeds if the key exists and returns an
//     error wrapping transhim.ErrKeyNotFound otherwise.
//   - DeleteKey deletes nothing from the KeyStore. It only drops the key from
//     this Backend's memory and succeeds. The data stays readable until the
//     key is deleted from the KeyStore by whoever manages it.
func ReadOnly() Option {
	return func(b *Backend) error {
		b.readOnly = true
		return nil
	}
}

type keyID struct{ mountID, name string }

type cachedKey struct {
	aead    cipher.AEAD
	expires time.Time
}

// Backend is a transhim.Backend and transhim.KeyLifecycle that encrypts with
// per-name intermediate keys. Create it with New.
type Backend struct {
	root        transhim.Backend
	rootKeyName string
	store       KeyStore
	ttl         time.Duration
	readOnly    bool
	now         func() time.Time

	mu    sync.Mutex
	cache map[keyID]cachedKey
	// gen counts deletions. A key that CreateKey stored while a deletion
	// happened is not cached: it may be the one that was just deleted. (Loads
	// are told about the deletion of their key through loading.)
	gen       uint64
	nextSweep time.Time

	// loads merges concurrent loads of the same key into one.
	loads singleflight.Group
	// loading holds the keys being loaded, so that DeleteKey can tell a load
	// that its key was deleted meanwhile. There is at most one load per key.
	loading map[keyID]*loadState
}

type loadState struct {
	// deleted is set by DeleteKey. Guarded by Backend.mu.
	deleted bool
}

// maxLoadAttempts bounds how often a load is repeated because its key was
// deleted while it ran.
const maxLoadAttempts = 3

var (
	_ transhim.Backend      = (*Backend)(nil)
	_ transhim.KeyLifecycle = (*Backend)(nil)
)

// New returns a Backend that wraps its intermediate keys with the key
// rootKeyName of the root backend and keeps them in store.
//
// rootKeyName is the only key name the root backend ever sees. The names of
// the keys served by the returned Backend only appear in the AAD of the root
// calls.
func New(root transhim.Backend, rootKeyName string, store KeyStore, opts ...Option) (*Backend, error) {
	if root == nil {
		return nil, errors.New("hierarchical: root backend must not be nil")
	}
	if rootKeyName == "" {
		return nil, errors.New("hierarchical: root key name must not be empty")
	}
	if store == nil {
		return nil, errors.New("hierarchical: key store must not be nil")
	}
	b := &Backend{
		root:        root,
		rootKeyName: rootKeyName,
		store:       store,
		ttl:         DefaultKeyCacheTTL,
		now:         time.Now,
		cache:       map[keyID]cachedKey{},
		loading:     map[keyID]*loadState{},
	}
	for _, opt := range opts {
		if err := opt(b); err != nil {
			return nil, fmt.Errorf("hierarchical: %w", err)
		}
	}
	return b, nil
}

// rootAAD binds a wrapped intermediate key to the mount and key name it
// belongs to:
//
//	"transhim/hierarchical/v1" || 0x00 || mount_id || 0x00 || key_name
//
// A stored key copied to another name therefore does not unwrap.
func rootAAD(mountID, keyName string) []byte {
	aad := make([]byte, 0, len(rootAADPrefix)+len(mountID)+len(keyName)+2)
	aad = append(aad, rootAADPrefix...)
	aad = append(aad, 0)
	aad = append(aad, mountID...)
	aad = append(aad, 0)
	aad = append(aad, keyName...)
	return aad
}

// rootError passes on what a caller can act on (the KMS is unavailable or
// refuses) and hides the rest. In particular, the root backend reporting a
// missing key or a mismatch is about the root key or the stored key, not about
// the client's key or ciphertext, so it must not reach the client as such.
func rootError(action string, err error) error {
	if errors.Is(err, transhim.ErrUpstream) || errors.Is(err, transhim.ErrPermissionDenied) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("hierarchical: %s: %w", action, err)
	}
	return fmt.Errorf("hierarchical: %s: %v", action, err)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// cached returns the cached key, if any, and the generation to pass to
// remember.
func (b *Backend) cached(id keyID) (cipher.AEAD, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if c, ok := b.cache[id]; ok {
		if b.now().Before(c.expires) {
			return c.aead, b.gen
		}
		delete(b.cache, id)
	}
	return nil, b.gen
}

// remember caches a key, unless a deletion happened since gen was read.
func (b *Backend) remember(id keyID, aead cipher.AEAD, gen uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if gen != b.gen {
		return
	}
	b.rememberLocked(id, aead)
}

// rememberLocked caches a key. The caller holds b.mu.
func (b *Backend) rememberLocked(id keyID, aead cipher.AEAD) {
	if b.ttl == 0 {
		return
	}
	now := b.now()
	if !now.Before(b.nextSweep) {
		// drop the keys of names that are not used anymore
		for k, c := range b.cache {
			if !now.Before(c.expires) {
				delete(b.cache, k)
			}
		}
		b.nextSweep = now.Add(b.ttl)
	}
	b.cache[id] = cachedKey{aead: aead, expires: now.Add(b.ttl)}
}

// key returns the cipher for the intermediate key of (mountID, keyName).
func (b *Backend) key(ctx context.Context, mountID, keyName string) (cipher.AEAD, error) {
	id := keyID{mountID, keyName}
	if aead, _ := b.cached(id); aead != nil {
		return aead, nil
	}
	// When a key is not in memory (first use, or its cache entry expired),
	// every request for it that arrives before the load finishes would call
	// the KeyStore and the root backend. The root backend is a KMS and may be
	// slow, and may serve concurrent calls one after the other. So the first
	// request loads the key and the others wait for it.
	//
	// The load must not die with the request that happened to start it, so
	// it does not inherit that request's cancellation.
	flightKey := fmt.Sprintf("%d:%s%s", len(mountID), mountID, keyName)
	for range maxLoadAttempts {
		v, err, _ := b.loads.Do(flightKey, func() (any, error) {
			return b.load(context.WithoutCancel(ctx), mountID, keyName)
		})
		if err != nil {
			return nil, err
		}
		// A key that was deleted while it was being loaded must not be handed
		// out: a request that arrived after the deletion may be waiting for
		// this very load, and would use the deleted key. Load again instead,
		// which finds the key gone (or a new one created since).
		if res := v.(loadResult); !res.deleted {
			return res.aead, nil
		}
	}
	return nil, fmt.Errorf("hierarchical: key %q was deleted repeatedly while it was being loaded", keyName)
}

type loadResult struct {
	aead cipher.AEAD
	// deleted reports that DeleteKey ran for the key during the load.
	deleted bool
}

// load fetches the intermediate key from the KeyStore and unwraps it. It runs
// at most once at a time per key.
func (b *Backend) load(ctx context.Context, mountID, keyName string) (loadResult, error) {
	id := keyID{mountID, keyName}
	state := &loadState{}
	b.mu.Lock()
	b.loading[id] = state
	b.mu.Unlock()
	aead, err := b.loadKey(ctx, id)
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.loading, id)
	if err == nil && !state.deleted {
		b.rememberLocked(id, aead)
	}
	return loadResult{aead: aead, deleted: state.deleted}, err
}

func (b *Backend) loadKey(ctx context.Context, id keyID) (cipher.AEAD, error) {
	mountID, keyName := id.mountID, id.name
	// a load that finished just before this one started may have cached it
	if aead, _ := b.cached(id); aead != nil {
		return aead, nil
	}
	stored, err := b.store.Get(ctx, mountID, keyName)
	if err != nil {
		return nil, fmt.Errorf("hierarchical: get key from store: %w", err)
	}
	raw, err := b.root.Decrypt(ctx, transhim.DecryptRequest{
		MountID: mountID,
		KeyName: b.rootKeyName,
		Wrapped: stored.Wrapped,
		AAD:     rootAAD(mountID, keyName),
	})
	if err != nil {
		return nil, rootError("unwrap intermediate key", err)
	}
	defer clear(raw)
	if len(raw) != intermediateKeySize {
		return nil, fmt.Errorf("hierarchical: stored intermediate key has %d bytes, want %d", len(raw), intermediateKeySize)
	}
	return newAEAD(raw)
}

// Encrypt implements transhim.Backend. It returns an error wrapping
// transhim.ErrKeyNotFound if the key was not created with CreateKey.
func (b *Backend) Encrypt(ctx context.Context, req transhim.EncryptRequest) (transhim.WrappedKey, error) {
	aead, err := b.key(ctx, req.MountID, req.KeyName)
	if err != nil {
		return transhim.WrappedKey{}, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(req.Plaintext)+aead.Overhead())
	rand.Read(nonce) // never fails
	return transhim.WrappedKey{
		KeyRef:  keyRef,
		Version: 1,
		Blob:    aead.Seal(nonce, nonce, req.Plaintext, req.AAD),
	}, nil
}

// Decrypt implements transhim.Backend.
func (b *Backend) Decrypt(ctx context.Context, req transhim.DecryptRequest) ([]byte, error) {
	// KeyRef and Version are not covered by the AAD, so check them here.
	if req.Wrapped.KeyRef != keyRef || req.Wrapped.Version != 1 {
		return nil, transhim.ErrCiphertextMismatch
	}
	aead, err := b.key(ctx, req.MountID, req.KeyName)
	if err != nil {
		return nil, err
	}
	blob := req.Wrapped.Blob
	if len(blob) < aead.NonceSize()+aead.Overhead() {
		return nil, transhim.ErrCiphertextMismatch
	}
	plaintext, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], req.AAD)
	if err != nil {
		return nil, transhim.ErrCiphertextMismatch
	}
	return plaintext, nil
}

// CreateKey implements transhim.KeyLifecycle. If the key exists, it is kept.
// Of several concurrent calls for the same key, one wins and the others adopt
// its key.
//
// With ReadOnly it creates nothing, and a key that does not exist is an error
// wrapping transhim.ErrKeyNotFound.
func (b *Backend) CreateKey(ctx context.Context, mountID, keyName string) error {
	// Usually the key is either new or was created long ago (RGW asks again
	// after DeleteBucketEncryption). Looking first saves a root call then.
	_, err := b.store.Get(ctx, mountID, keyName)
	if err == nil {
		return nil
	}
	if !errors.Is(err, transhim.ErrKeyNotFound) {
		return fmt.Errorf("hierarchical: get key from store: %w", err)
	}
	if b.readOnly {
		return fmt.Errorf("hierarchical: the key is not in the store, and a read-only backend does not create it: %w", transhim.ErrKeyNotFound)
	}

	id := keyID{mountID, keyName}
	_, gen := b.cached(id)
	raw := make([]byte, intermediateKeySize)
	rand.Read(raw) // never fails
	defer clear(raw)
	wrapped, err := b.root.Encrypt(ctx, transhim.EncryptRequest{
		MountID:   mountID,
		KeyName:   b.rootKeyName,
		Plaintext: raw,
		AAD:       rootAAD(mountID, keyName),
	})
	if err != nil {
		return rootError("wrap intermediate key", err)
	}
	aead, err := newAEAD(raw)
	if err != nil {
		return err
	}
	err = b.store.PutIfAbsent(ctx, mountID, keyName, StoredKey{Wrapped: wrapped, CreatedAt: b.now()})
	if errors.Is(err, ErrKeyExists) {
		// someone else created it meanwhile: their key wins, ours is dropped
		return nil
	}
	if err != nil {
		return fmt.Errorf("hierarchical: put key into store: %w", err)
	}
	b.remember(id, aead, gen)
	return nil
}

// DeleteKey implements transhim.KeyLifecycle. This is the crypto-shredding
// point: without the intermediate key, nothing encrypted with it can be read.
// See the package documentation for how long other instances keep the key.
//
// With ReadOnly it leaves the KeyStore alone and only forgets the key.
func (b *Backend) DeleteKey(ctx context.Context, mountID, keyName string) error {
	var err error
	if !b.readOnly {
		err = b.store.Delete(ctx, mountID, keyName)
	}
	// Forget the key even if the store failed: it may be gone all the same.
	id := keyID{mountID, keyName}
	b.mu.Lock()
	b.gen++
	delete(b.cache, id)
	if state := b.loading[id]; state != nil {
		state.deleted = true
	}
	b.mu.Unlock()
	if err != nil {
		return fmt.Errorf("hierarchical: delete key from store: %w", err)
	}
	return nil
}
