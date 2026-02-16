package mem_cache

import (
	"sync/atomic"
	"time"

	"github.com/pmkol/mosdns-x/pkg/concurrent_lru"
)

const (
	// shardSize must be a power of 2 (e.g., 64, 128, 256).
	// This is required for efficient bitwise shard indexing.
	shardSize              = 128
	defaultCleanerInterval = time.Minute
)

type MemCache struct {
	closed           uint32
	closeCleanerChan chan struct{}
	lru              *concurrent_lru.ShardedLRU[*elem]
}

type elem struct {
	v  []byte
	st int64
	ex int64
}

func NewMemCache(size int, cleanerInterval time.Duration) *MemCache {
	if size <= 0 {
		size = shardSize * 16
	}

	sizePerShard := size / shardSize
	if sizePerShard < 16 {
		sizePerShard = 16
	}

	c := &MemCache{
		closeCleanerChan: make(chan struct{}),
		lru: concurrent_lru.NewShardedLRU[*elem](
			shardSize,
			sizePerShard,
			nil,
		),
	}

	if cleanerInterval > 0 {
		go c.startCleaner(cleanerInterval)
	}

	return c
}

func (c *MemCache) isClosed() bool {
	return atomic.LoadUint32(&c.closed) != 0
}

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

	e, ok := c.lru.Get(key)
	if !ok {
		return nil, time.Time{}, time.Time{}
	}

	return e.v,
		time.Unix(e.st, 0),
		time.Unix(e.ex, 0)
}

func (c *MemCache) Store(
	key string,
	v []byte,
	storedTime,
	expirationTime time.Time,
) {
	if c.isClosed() {
		return
	}

	c.lru.Add(key, &elem{
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
