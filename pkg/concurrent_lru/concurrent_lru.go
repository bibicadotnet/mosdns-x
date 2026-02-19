package concurrent_lru

import (
	"sync"

	"github.com/pmkol/mosdns-x/pkg/lru"
)

type ShardedLRU[V any] struct {
	l    []*ConcurrentLRU[uint64, V]
	mask uint64 // shardNum - 1 (shardNum must be power of 2)
}

func NewShardedLRU[V any](
	shardNum, maxSizePerShard int,
	onEvict func(key uint64, v V),
) *ShardedLRU[V] {

	if shardNum <= 0 || shardNum&(shardNum-1) != 0 {
		panic("shardNum must be a power of 2 and > 0")
	}

	cl := &ShardedLRU[V]{
		l:    make([]*ConcurrentLRU[uint64, V], shardNum),
		mask: uint64(shardNum - 1),
	}

	for i := range cl.l {
		cl.l[i] = &ConcurrentLRU[uint64, V]{
			lru: lru.NewLRU[uint64, V](maxSizePerShard, onEvict),
		}
	}

	return cl
}

func (c *ShardedLRU[V]) getShard(key uint64) *ConcurrentLRU[uint64, V] {
	return c.l[int(key&c.mask)]
}

func (c *ShardedLRU[V]) Add(key uint64, v V) {
	c.getShard(key).Add(key, v)
}

func (c *ShardedLRU[V]) Del(key uint64) {
	c.getShard(key).Del(key)
}

func (c *ShardedLRU[V]) Get(key uint64) (v V, ok bool) {
	return c.getShard(key).Get(key)
}

func (c *ShardedLRU[V]) Clean(f func(key uint64, v V) bool) (removed int) {
	for _, shard := range c.l {
		removed += shard.Clean(f)
	}
	return
}

func (c *ShardedLRU[V]) Len() int {
	sum := 0
	for _, shard := range c.l {
		sum += shard.Len()
	}
	return sum
}

// -----------------------------

type ConcurrentLRU[K comparable, V any] struct {
	sync.Mutex
	lru *lru.LRU[K, V]
}

func NewConcurrentLRU[K comparable, V any](
	maxSize int,
	onEvict func(key K, v V),
) *ConcurrentLRU[K, V] {
	return &ConcurrentLRU[K, V]{
		lru: lru.NewLRU[K, V](maxSize, onEvict),
	}
}

func (c *ConcurrentLRU[K, V]) Add(key K, v V) {
	c.Lock()
	c.lru.Add(key, v)
	c.Unlock()
}

func (c *ConcurrentLRU[K, V]) Del(key K) {
	c.Lock()
	c.lru.Del(key)
	c.Unlock()
}

func (c *ConcurrentLRU[K, V]) Get(key K) (v V, ok bool) {
	c.Lock()
	v, ok = c.lru.Get(key)
	c.Unlock()
	return
}

func (c *ConcurrentLRU[K, V]) Clean(f func(key K, v V) bool) (removed int) {
	c.Lock()
	removed = c.lru.Clean(f)
	c.Unlock()
	return
}

func (c *ConcurrentLRU[K, V]) Len() int {
	c.Lock()
	n := c.lru.Len()
	c.Unlock()
	return n
}
