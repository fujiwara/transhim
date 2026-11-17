package transhim

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// DecryptCacheConfig configures the decrypt cache.
//
// The cache holds plaintext data keys in memory. TTL is therefore also the
// longest time a revocation takes to become effective when it is made behind
// the server's back: disabling a key directly in the KMS, or deleting a key
// through another server instance. Deleting a key through this server removes
// its entries at once.
type DecryptCacheConfig struct {
	// MaxEntries bounds the cache. The least recently used entry is evicted
	// first. Required.
	MaxEntries int
	// TTL is how long an entry may be served after it was stored. Required.
	TTL time.Duration
	// WarmOnDatakey also stores the keys handed out by datakey, so that the
	// first decrypt of a new data key is already a hit.
	WarmOnDatakey bool
}

func (c DecryptCacheConfig) validate() error {
	if c.MaxEntries <= 0 {
		return errors.New("decrypt cache: MaxEntries must be positive")
	}
	if c.TTL <= 0 {
		return errors.New("decrypt cache: TTL must be positive")
	}
	return nil
}

// cacheKey identifies one decrypt request:
//
//	sha256(lp(mount_id) || lp(key_name) || lp(context) || envelope)
//
// with lp(x) = uvarint(len(x)) || x. Length prefixes keep the fields apart
// even though context is arbitrary bytes.
type cacheKey [sha256.Size]byte

func newCacheKey(mountID, keyName string, context []byte, envelope string) cacheKey {
	h := sha256.New()
	var lenBuf [binary.MaxVarintLen64]byte
	lp := func(b []byte) {
		h.Write(lenBuf[:binary.PutUvarint(lenBuf[:], uint64(len(b)))])
		h.Write(b)
	}
	lp([]byte(mountID))
	lp([]byte(keyName))
	lp(context)
	h.Write([]byte(envelope))
	var k cacheKey
	h.Sum(k[:0])
	return k
}

// keyID names a key within a server.
type keyID struct{ mountID, name string }

type cacheEntry struct {
	key       cacheKey
	id        keyID
	plaintext []byte
	expires   time.Time
}

// decryptCache is an LRU cache of decrypt results with a TTL. It is safe for
// concurrent use.
type decryptCache struct {
	maxEntries int
	ttl        time.Duration
	now        func() time.Time

	mu    sync.Mutex
	lru   *list.List // of *cacheEntry, most recently used first
	items map[cacheKey]*list.Element
	// byKey finds the entries of one key, for invalidation.
	byKey map[keyID]map[cacheKey]struct{}
	// gen counts invalidations. See put.
	gen uint64
}

func newDecryptCache(cfg DecryptCacheConfig) *decryptCache {
	return &decryptCache{
		maxEntries: cfg.MaxEntries,
		ttl:        cfg.TTL,
		now:        time.Now,
		lru:        list.New(),
		items:      map[cacheKey]*list.Element{},
		byKey:      map[keyID]map[cacheKey]struct{}{},
	}
}

// get returns a copy of the cached plaintext.
func (c *decryptCache) get(k cacheKey) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[k]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if !c.now().Before(e.expires) {
		c.remove(el)
		return nil, false
	}
	c.lru.MoveToFront(el)
	return append([]byte(nil), e.plaintext...), true
}

// generation returns a value to pass to put. It must be read before the
// backend call whose result is going to be stored.
func (c *decryptCache) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// put stores a copy of plaintext, unless an invalidation happened since gen
// was read. Without that check, a decrypt that was in flight while its key was
// deleted would bring the key's plaintext back into the cache.
func (c *decryptCache) put(k cacheKey, id keyID, plaintext []byte, gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen {
		return
	}
	if el, ok := c.items[k]; ok {
		c.remove(el)
	}
	e := &cacheEntry{
		key:       k,
		id:        id,
		plaintext: append([]byte(nil), plaintext...),
		expires:   c.now().Add(c.ttl),
	}
	c.items[k] = c.lru.PushFront(e)
	if c.byKey[id] == nil {
		c.byKey[id] = map[cacheKey]struct{}{}
	}
	c.byKey[id][k] = struct{}{}
	for c.lru.Len() > c.maxEntries {
		c.remove(c.lru.Back())
	}
}

// invalidate removes every entry of a key.
func (c *decryptCache) invalidate(id keyID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	for k := range c.byKey[id] {
		c.remove(c.items[k])
	}
}

// remove drops an entry and zeroes its plaintext (best effort: copies handed
// out earlier are not reachable from here). The caller holds c.mu.
func (c *decryptCache) remove(el *list.Element) {
	e := c.lru.Remove(el).(*cacheEntry)
	clear(e.plaintext)
	delete(c.items, e.key)
	if keys := c.byKey[e.id]; keys != nil {
		delete(keys, e.key)
		if len(keys) == 0 {
			delete(c.byKey, e.id)
		}
	}
}

func (c *decryptCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
