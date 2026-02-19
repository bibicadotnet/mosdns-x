package pool

import (
	"math/bits"
	"sync"
)

// Limit pool to 12 bits (4KB).
// Optimized for DNS workloads (UDP/DoH/DoT/DoQ).
const maxDNSPoolBits = 12

// defaultBufPool manages 13 shards (2^0 to 2^12).
var defaultBufPool = NewAllocator(maxDNSPoolBits)

// GetBuf returns a *Buffer from the default pool with the most appropriate capacity.
func GetBuf(size int) *Buffer {
	return defaultBufPool.Get(size)
}

type Allocator struct {
	maxPoolLen int
	buffers    []sync.Pool
}

// NewAllocator initiates a byte buffer allocator.
func NewAllocator(maxPoolBitsLen int) *Allocator {
	if maxPoolBitsLen <= 0 || maxPoolBitsLen > 12 {
		maxPoolBitsLen = 12
	}

	ml := 1 << maxPoolBitsLen
	alloc := &Allocator{
		maxPoolLen: ml,
		buffers:    make([]sync.Pool, maxPoolBitsLen+1),
	}

	for i := range alloc.buffers {
		// Fix closure capture by defining 'size' inside the loop.
		size := 1 << i
		alloc.buffers[i].New = func() interface{} {
			return newBuffer(alloc, make([]byte, size))
		}
	}
	return alloc
}

// Get returns a *Buffer from the pool.
// Fallback to direct allocation (a == nil) if size exceeds maxPoolLen.
func (alloc *Allocator) Get(size int) *Buffer {
	if size < 0 {
		size = 0
	}

	if size > alloc.maxPoolLen {
		return &Buffer{
			a: nil,
			l: size,
			b: make([]byte, size),
		}
	}

	i := shard(size)
	buf := alloc.buffers[i].Get().(*Buffer)
	buf.SetLen(size)
	return buf
}

// Release returns the buffer to the pool. Safely ignores unmanaged or invalid buffers.
func (alloc *Allocator) Release(buf *Buffer) {
	if buf == nil || buf.a == nil {
		return
	}

	c := buf.Cap()
	if c == 0 || c > alloc.maxPoolLen {
		return
	}

	i := shard(c)
	// Fragmentation check: Only pool buffers matching power-of-two shards.
	if c != (1 << i) {
		return
	}

	// Reset logical length to 0 before returning to pool.
	// This maintains the invariant that a free buffer is an empty buffer.
	buf.l = 0
	alloc.buffers[i].Put(buf)
}

// shard returns the shard index suitable for the size.
func shard(size int) int {
	if size <= 1 {
		return 0
	}
	return bits.Len(uint(size - 1))
}

// Buffer wraps a byte slice with its allocator reference.
type Buffer struct {
	a *Allocator
	l int
	b []byte
}

func newBuffer(a *Allocator, b []byte) *Buffer {
	return &Buffer{
		a: a,
		l: len(b),
		b: b,
	}
}

// SetLen adjusts the logical length of the buffer.
func (b *Buffer) SetLen(l int) {
	if l > len(b.b) {
		l = len(b.b)
	}
	b.l = l
}

func (b *Buffer) AllBytes() []byte { return b.b }
func (b *Buffer) Bytes() []byte    { return b.b[:b.l] }
func (b *Buffer) Len() int         { return b.l }
func (b *Buffer) Cap() int         { return cap(b.b) }

// Release returns the buffer to its allocator.
func (b *Buffer) Release() {
	if b.a != nil {
		b.a.Release(b)
	}
}
