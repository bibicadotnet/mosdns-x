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
	packet     []byte
	storedTime int64 // Unix second - dùng để tính Subtract TTL
	expire     int64 // Unix nano - mốc hết hạn thực tế
	lazyExpire int64 // Unix nano - mốc hết hạn sau khi cộng thêm Lazy TTL
	ttlOffsets [8]uint16
	ttlCount   uint8
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

func (c *MemCache) Get(key string) (packet []byte, storedTime int64, offsets [8]uint16, count uint8, lazyHit bool, ok bool) {
	if c.isClosed() {
		return nil, 0, [8]uint16{}, 0, false, false
	}

	e, found := c.lru.Get(key)
	if !found {
		return nil, 0, [8]uint16{}, 0, false, false
	}

	now := time.Now().UnixNano()

	// Quá hạn hoàn toàn (vượt cả cửa sổ Lazy)
	if now > e.lazyExpire {
		return nil, 0, [8]uint16{}, 0, false, false
	}

	// Trả về gói tin và trạng thái
	lazyHit = now > e.expire
	return e.packet, e.storedTime, e.ttlOffsets, e.ttlCount, lazyHit, true
}

func (c *MemCache) Store(key string, packet []byte, expire, lazyExpire int64, offsets [8]uint16, count uint8) {
	if c.isClosed() {
		return
	}

	// Copy sang buffer mới để Backend làm chủ vùng nhớ
	buf := make([]byte, len(packet))
	copy(buf, packet)

	c.lru.Add(key, &elem{
		packet:     buf,
		storedTime: time.Now().Unix(),
		expire:     expire,
		lazyExpire: lazyExpire,
		ttlOffsets: offsets,
		ttlCount:   count,
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
			c.lru.Clean(func(_ string, e *elem) bool {
				return e.lazyExpire <= now
			})
		}
	}
}

func (c *MemCache) Len() int {
	return c.lru.Len()
}
