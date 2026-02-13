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
	v  []byte
	st int64 // storedTime as Unix timestamp
	ex int64 // expirationTime as Unix timestamp
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

func (c *MemCache) Get(key string) (v []byte, storedTime, expirationTime time.Time) {
	if c.isClosed() {
		return nil, time.Time{}, time.Time{}
	}

	if e, ok := c.lru.Get(key); ok {
		return e.v, time.Unix(e.st, 0), time.Unix(e.ex, 0)
	}

	return nil, time.Time{}, time.Time{}
}

// Store saves an entry. The caller is responsible for TTL validation.
func (c *MemCache) Store(key string, v []byte, storedTime, expirationTime time.Time) {
	if c.isClosed() {
		return
	}

	c.lru.Add(key, &elem{
		// The caller is responsible for not mutating v after Store returns.
		// This allows the cache backend to avoid an extra copy and improves
		// performance for high-throughput scenarios.
		v:  v,
		st: storedTime.Unix(),
		ex: expirationTime.Unix(),
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
			now := time.Now().Unix()
			c.lru.Clean(func(_ string, e *elem) bool {
				return e.ex <= now
			})
		}
	}
}

func (c *MemCache) Len() int {
	return c.lru.Len()
}
