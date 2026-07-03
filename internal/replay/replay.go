// Package replay remembers redeemed challenges so a solved challenge
// cannot be exchanged for more than one cookie during its lifetime.
//
// This is the one piece of state in powd, and it is deliberately modest:
// a mutex-guarded map plus a redemption-order queue, bounded in both time
// (entries are dropped once their challenge has expired, after which the
// token itself no longer verifies) and space (at capacity the oldest
// entries are evicted — powd degrades toward weaker replay protection
// under memory pressure rather than crashing or blocking).
//
// Issuing challenges remains completely stateless; only redemption
// touches this cache.
package replay

import (
	"sync"
	"time"
)

// DefaultMax is the entry cap used when New is given a non-positive max.
// At ~90 bytes per entry this bounds the cache near 6 MB.
const DefaultMax = 1 << 16

type entry struct {
	id     string
	expiry time.Time
}

// Cache is a bounded set of redeemed challenge IDs. It is safe for
// concurrent use.
type Cache struct {
	mu   sync.Mutex
	max  int
	seen map[string]time.Time // id → challenge expiry
	fifo []entry              // redemption order, for pruning and eviction
}

// New returns a Cache holding at most max entries.
func New(max int) *Cache {
	if max <= 0 {
		max = DefaultMax
	}
	return &Cache{max: max, seen: make(map[string]time.Time)}
}

// Redeem records id as redeemed until expiry and reports whether this is
// its first redemption; false means replay. The caller must have already
// authenticated the challenge and checked its expiry — id and expiry are
// trusted to come from a verified token.
func (c *Cache) Redeem(now time.Time, id string, expiry time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Drop entries whose challenge has expired: the token no longer
	// verifies, so remembering it protects nothing. All challenges share
	// one TTL, so redemption order approximates expiry order and pruning
	// from the front is enough.
	for len(c.fifo) > 0 && now.After(c.fifo[0].expiry) {
		delete(c.seen, c.fifo[0].id)
		c.fifo = c.fifo[1:]
	}

	if _, ok := c.seen[id]; ok {
		return false
	}

	// At capacity, evict the oldest redemption even if unexpired.
	for len(c.fifo) >= c.max {
		delete(c.seen, c.fifo[0].id)
		c.fifo = c.fifo[1:]
	}

	c.seen[id] = expiry
	c.fifo = append(c.fifo, entry{id, expiry})
	return true
}

// Len returns the current number of remembered redemptions.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
