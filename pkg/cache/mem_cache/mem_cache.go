package mem_cache

import (
	"sync/atomic"
	"time"

	"github.com/pmkol/mosdns-x/pkg/concurrent_lru"
)

const (
	shardSize              = 64
	defaultCleanerInterval = time.Minute
)

// MemCache is a simple LRU cache that stores values in memory.
// It is safe for concurrent use.
type MemCache struct {
	closed           uint32
	closeCleanerChan chan struct{}
	lru              *concurrent_lru.ShardedLRU[*elem]
}

type elem struct {
	packet     []byte
	expire     int64 // Unix nano - Actual DNS record TTL
	lazyExpire int64 // Unix nano - expire + lazy_cache_ttl
}

// NewMemCache initializes a MemCache.
// cleanerInterval <= 0 disables the background cleaner (passive mode).
func NewMemCache(size int, cleanerInterval time.Duration) *MemCache {
	sizePerShard := size / shardSize
	if sizePerShard < 16 {
		sizePerShard = 16
	}
	c := &MemCache{
		closeCleanerChan: make(chan struct{}),
		lru:              concurrent_lru.NewShardedLRU[*elem](shardSize, sizePerShard, nil),
	}

	// Optional cleaner
	if cleanerInterval > 0 {
		go c.startCleaner(cleanerInterval)
	}

	return c
}

func (c *MemCache) isClosed() bool {
	return atomic.LoadUint32(&c.closed) != 0
}

// Close closes the cache and its cleaner.
func (c *MemCache) Close() error {
	if atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		close(c.closeCleanerChan)
	}
	return nil
}

// Get returns (packet, lazyHit, ok)
// - lazyHit = true: record expired but within lazy window
// - lazyHit = false: record fresh or miss
// Note: It returns the raw internal slice. The caller is responsible for 
// copying the packet if modification (e.g., patching ID) is required.
func (c *MemCache) Get(key string) (packet []byte, lazyHit bool, ok bool) {
	if c.isClosed() {
		return nil, false, false
	}

	e, found := c.lru.Get(key)
	if !found {
		return nil, false, false
	}

	now := time.Now().UnixNano()

	// Fully expired (exceeds lazy window)
	if now > e.lazyExpire {
		return nil, false, false
	}

	// Stale (lazy hit)
	if now > e.expire {
		return e.packet, true, true
	}

	// Fresh hit
	return e.packet, false, true
}

// Store saves packet with expire and lazyExpire timestamps (Unix nano)
func (c *MemCache) Store(key string, packet []byte, expire, lazyExpire int64) {
	if c.isClosed() {
		return
	}

	// Create a dedicated copy for the cache to own
	buf := make([]byte, len(packet))
	copy(buf, packet)

	c.lru.Add(key, &elem{
		packet:     buf,
		expire:     expire,
		lazyExpire: lazyExpire,
	})
}

func (c *MemCache) startCleaner(interval time.Duration) {
	if interval <= 0 {
		interval = defaultCleanerInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.closeCleanerChan:
			return
		case <-ticker.C:
			now := time.Now().UnixNano()
			// Only evict entries that have exceeded their lazy retention window
			c.lru.Clean(func(_ string, e *elem) bool {
				return e.lazyExpire <= now
			})
		}
	}
}

func (c *MemCache) Len() int {
	return c.lru.Len()
}
