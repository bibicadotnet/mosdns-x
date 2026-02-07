package mem_cache

import (
	"sync/atomic"
	"time"

	"github.com/pmkol/mosdns-x/pkg/concurrent_lru"
)

// MemCache is a size-bounded, high-performance passive LRU store.
// 
// LIFECYCLE MANAGEMENT:
// 1. Physical Eviction (RAM): Managed strictly by LRU capacity (Size). 
//    Memory usage will grow until it reaches the configured limit and stay there. 
//    This is INTENTIONAL behavior to maximize speed, not a memory leak.
// 2. Logical Expiration (TTL): Enforced by the upper cache plugin logic 
//    (e.g., plugin/executable/cache) using the 7-byte fast-path header.
//
// DO NOT add background timers or "cleaners" here. This design avoids 
// CPU spikes and GC pressure by being entirely passive.
type MemCache struct {
	closed uint32
	lru    *concurrent_lru.ShardedLRU[*elem]
}

type elem struct {
	v  []byte // slice header (24B)
	st int64  // storedTime.Unix() (8B)
	ex int64  // expirationTime.Unix() (8B)
}

// NewMemCache creates a passive storage backend.
// The cleanerInterval argument is ignored as eviction is strictly size-based.
func NewMemCache(size int, _ time.Duration) *MemCache {
	sizePerShard := size / 64
	if sizePerShard < 16 {
		sizePerShard = 16
	}

	return &MemCache{
		lru: concurrent_lru.NewShardedLRU[*elem](64, sizePerShard, nil),
	}
}

func (c *MemCache) isClosed() bool {
	return atomic.LoadUint32(&c.closed) != 0
}

// Get retrieves an entry. The caller MUST validate TTL/Expiration.
func (c *MemCache) Get(key string) ([]byte, time.Time, time.Time) {
	if c.isClosed() {
		return nil, time.Time{}, time.Time{}
	}

	if e, ok := c.lru.Get(key); ok {
		return e.v, time.Unix(e.st, 0), time.Unix(e.ex, 0)
	}
	return nil, time.Time{}, time.Time{}
}

func (c *MemCache) Store(key string, v []byte, st, ex time.Time) {
	if c.isClosed() {
		return
	}

	// Data is copied to ensure immutability within the cache.
	buf := make([]byte, len(v))
	copy(buf, v)

	c.lru.Add(key, &elem{
		v:  buf,
		st: st.Unix(),
		ex: ex.Unix(),
	})
}

func (c *MemCache) Close() error {
	atomic.StoreUint32(&c.closed, 1)
	return nil
}

func (c *MemCache) Len() int {
	return c.lru.Len()
}
