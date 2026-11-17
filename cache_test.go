package transhim

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestCache(maxEntries int, ttl time.Duration) (*decryptCache, *fakeClock) {
	clock := &fakeClock{t: time.Unix(1700000000, 0)}
	c := newDecryptCache(DecryptCacheConfig{MaxEntries: maxEntries, TTL: ttl})
	c.now = clock.now
	return c, clock
}

func testKey(i int) cacheKey {
	return newCacheKey("m", "k", nil, fmt.Sprintf("vault:v1:%d", i))
}

func TestCacheKey(t *testing.T) {
	base := newCacheKey("m", "k", []byte("ctx"), "vault:v1:AAAA")
	if base != newCacheKey("m", "k", []byte("ctx"), "vault:v1:AAAA") {
		t.Error("cache key is not deterministic")
	}
	others := map[string]cacheKey{
		"mount":      newCacheKey("m2", "k", []byte("ctx"), "vault:v1:AAAA"),
		"key name":   newCacheKey("m", "k2", []byte("ctx"), "vault:v1:AAAA"),
		"context":    newCacheKey("m", "k", []byte("ctx2"), "vault:v1:AAAA"),
		"no context": newCacheKey("m", "k", nil, "vault:v1:AAAA"),
		"envelope":   newCacheKey("m", "k", []byte("ctx"), "vault:v1:AAAB"),
		// moving bytes between fields must change the key
		"mount/key":     newCacheKey("mk", "", []byte("ctx"), "vault:v1:AAAA"),
		"key/context":   newCacheKey("m", "kc", []byte("tx"), "vault:v1:AAAA"),
		"context/envel": newCacheKey("m", "k", []byte("ctxv"), "ault:v1:AAAA"),
	}
	for name, k := range others {
		if k == base {
			t.Errorf("a different %s gives the same cache key", name)
		}
	}
}

func TestCacheGetPut(t *testing.T) {
	c, _ := newTestCache(10, time.Minute)
	id := keyID{"m", "k"}
	if _, ok := c.get(testKey(1)); ok {
		t.Error("hit on an empty cache")
	}
	plaintext := []byte("secret")
	c.put(testKey(1), id, plaintext, c.generation())
	clear(plaintext) // the cache must hold its own copy

	got, ok := c.get(testKey(1))
	if !ok || string(got) != "secret" {
		t.Fatalf("get = %q, %v", got, ok)
	}
	clear(got) // and hand out copies
	if got, _ := c.get(testKey(1)); string(got) != "secret" {
		t.Errorf("second get = %q", got)
	}

	c.put(testKey(1), id, []byte("replaced"), c.generation())
	if got, _ := c.get(testKey(1)); string(got) != "replaced" || c.len() != 1 {
		t.Errorf("after replacing: get = %q, len = %d", got, c.len())
	}
}

func TestCacheTTL(t *testing.T) {
	c, clock := newTestCache(10, time.Minute)
	c.put(testKey(1), keyID{"m", "k"}, []byte("p"), c.generation())
	clock.advance(time.Minute - time.Nanosecond)
	if _, ok := c.get(testKey(1)); !ok {
		t.Error("miss before the TTL")
	}
	// a hit does not extend the lifetime
	clock.advance(time.Nanosecond)
	if _, ok := c.get(testKey(1)); ok {
		t.Error("hit at the TTL")
	}
	if c.len() != 0 || len(c.byKey) != 0 {
		t.Errorf("expired entry was not removed: len = %d, index = %d", c.len(), len(c.byKey))
	}
}

func TestCacheLRU(t *testing.T) {
	c, _ := newTestCache(3, time.Minute)
	id := keyID{"m", "k"}
	for i := 1; i <= 3; i++ {
		c.put(testKey(i), id, []byte{byte(i)}, c.generation())
	}
	c.get(testKey(1)) // 2 is now the least recently used
	c.put(testKey(4), id, []byte{4}, c.generation())
	if c.len() != 3 {
		t.Errorf("len = %d, want 3", c.len())
	}
	for i, want := range map[int]bool{1: true, 2: false, 3: true, 4: true} {
		if _, ok := c.get(testKey(i)); ok != want {
			t.Errorf("entry %d: present = %v, want %v", i, ok, want)
		}
	}
	if n := len(c.byKey[id]); n != 3 {
		t.Errorf("index holds %d entries, want 3", n)
	}
}

func TestCacheInvalidate(t *testing.T) {
	c, _ := newTestCache(10, time.Minute)
	a, b := keyID{"m", "a"}, keyID{"m", "b"}
	otherMount := keyID{"m2", "a"}
	c.put(testKey(1), a, []byte("a1"), c.generation())
	c.put(testKey(2), a, []byte("a2"), c.generation())
	c.put(testKey(3), b, []byte("b"), c.generation())
	c.put(testKey(4), otherMount, []byte("o"), c.generation())

	// keep a reference to the stored bytes to see them being zeroed
	stored := c.items[testKey(1)].Value.(*cacheEntry).plaintext
	c.invalidate(a)
	if !bytes.Equal(stored, []byte{0, 0}) {
		t.Errorf("plaintext was not zeroed: %q", stored)
	}
	for i, want := range map[int]bool{1: false, 2: false, 3: true, 4: true} {
		if _, ok := c.get(testKey(i)); ok != want {
			t.Errorf("entry %d: present = %v, want %v", i, ok, want)
		}
	}
	if _, ok := c.byKey[a]; ok || c.len() != 2 {
		t.Errorf("index still knows the key, or len = %d", c.len())
	}
	c.invalidate(keyID{"m", "unknown"}) // no entries: fine
}

// TestCacheInvalidateDuringDecrypt: a decrypt that was in flight when its key
// was deleted must not put the plaintext back.
func TestCacheInvalidateDuringDecrypt(t *testing.T) {
	c, _ := newTestCache(10, time.Minute)
	id := keyID{"m", "k"}
	gen := c.generation() // decrypt starts
	c.invalidate(id)      // key is deleted meanwhile
	c.put(testKey(1), id, []byte("p"), gen)
	if _, ok := c.get(testKey(1)); ok {
		t.Error("a stale decrypt result was cached after invalidation")
	}
	c.put(testKey(1), id, []byte("p"), c.generation())
	if _, ok := c.get(testKey(1)); !ok {
		t.Error("a fresh result was not cached")
	}
}

func TestCacheConcurrent(t *testing.T) {
	c, _ := newTestCache(50, time.Minute)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			id := keyID{"m", fmt.Sprint(g % 3)}
			for i := range 500 {
				k := testKey(g*1000 + i%80)
				c.put(k, id, []byte("plaintext"), c.generation())
				if p, ok := c.get(k); ok && string(p) != "plaintext" {
					t.Errorf("got %q", p)
				}
				if i%50 == 0 {
					c.invalidate(id)
				}
			}
		})
	}
	wg.Wait()
	if c.len() > 50 {
		t.Errorf("len = %d, want at most 50", c.len())
	}
	n := 0
	for _, keys := range c.byKey {
		n += len(keys)
	}
	if n != c.len() || len(c.items) != c.len() {
		t.Errorf("index holds %d, map %d, list %d entries", n, len(c.items), c.len())
	}
}
