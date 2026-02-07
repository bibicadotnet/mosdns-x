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

type MemCache struct {
	closed           uint32
	closeCleanerChan chan struct{}
	lru              *concurrent_lru.ShardedLRU[*elem]
}

type elem struct {
	v  []byte // slice header (24B)
	st int64  // storedTime.Unix() (8B)
	ex int64  // expirationTime.Unix() (8B) - Bao gồm cả Lazy TTL
}

func NewMemCache(size int, cleanerInterval time.Duration) *MemCache {
	sizePerShard := size / shardSize
	if sizePerShard < 16 {
		sizePerShard = 16
	}

	c := &MemCache{
		closeCleanerChan: make(chan struct{}),
		lru:              concurrent_lru.NewShardedLRU[*elem](shardSize, sizePerShard, nil),
	}
	go c.startCleaner(cleanerInterval)
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

	if e, ok := c.lru.Get(key); ok {
		return e.v, time.Unix(e.st, 0), time.Unix(e.ex, 0)
	}
	return nil, time.Time{}, time.Time{}
}

func (c *MemCache) Store(key string, v []byte, storedTime, expirationTime time.Time) {
	if c.isClosed() {
		return
	}

	buf := make([]byte, len(v))
	copy(buf, v)

	e := &elem{
		v:  buf,
		st: storedTime.Unix(),
		ex: expirationTime.Unix(),
	}
	c.lru.Add(key, e)
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
			c.lru.Clean(c.cleanFunc())
		}
	}
}

func (c *MemCache) cleanFunc() func(_ string, e *elem) bool {
	// Lấy mốc Unix hiện tại một lần cho mỗi lượt quét
	nowUnix := time.Now().Unix()
	return func(_ string, e *elem) bool {
		// Xóa ngay khi chạm mốc hoặc vượt quá expiration time
		return e.ex <= nowUnix
	}
}

func (c *MemCache) Len() int {
	return c.lru.Len()
}
