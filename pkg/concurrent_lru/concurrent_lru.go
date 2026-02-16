package concurrent_lru

import (
	"hash/maphash"
	"sync"

	"github.com/pmkol/mosdns-x/pkg/lru"
)

type ShardedLRU[V any] struct {
	seed maphash.Seed
	l    []*ConcurrentLRU[string, V]
	mask uint64 // shardNum - 1 (shardNum must be power of 2)
}

func NewShardedLRU[V any](
	shardNum, maxSizePerShard int,
	onEvict func(key string, v V),
) *ShardedLRU[V] {

	if shardNum <= 0 || shardNum&(shardNum-1) != 0 {
		panic("shardNum must be a power of 2 and > 0")
	}

	cl := &ShardedLRU[V]{
		seed: maphash.MakeSeed(),
		l:    make([]*ConcurrentLRU[string, V], shardNum),
		mask: uint64(shardNum - 1),
	}

	for i := range cl.l {
		cl.l[i] = &ConcurrentLRU[string, V]{
			lru: lru.NewLRU[string, V](maxSizePerShard, onEvict),
		}
	}

	return cl
}

func (c *ShardedLRU[V]) getShard(key string) *ConcurrentLRU[string, V] {
	h := maphash.String(c.seed, key)
	return c.l[int(h&c.mask)]
}

func (c *ShardedLRU[V]) Add(key string, v V) {
	c.getShard(key).Add(key, v)
}

func (c *ShardedLRU[V]) Del(key string) {
	c.getShard(key).Del(key)
}

func (c *ShardedLRU[V]) Get(key string) (v V, ok bool) {
	return c.getShard(key).Get(key)
}

func (c *ShardedLRU[V]) Clean(f func(key string, v V) bool) (removed int) {
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
