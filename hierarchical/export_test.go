package hierarchical

import "time"

// SetNow replaces the clock of b.
func SetNow(b *Backend, now func() time.Time) { b.now = now }

// CacheLen returns the number of cached intermediate keys of b.
func CacheLen(b *Backend) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.cache)
}

// RootAAD exposes rootAAD.
var RootAAD = rootAAD
