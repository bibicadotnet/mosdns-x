package pool

import (
	"bytes"
	"sync"
)

// BytesBufPool is a pool for bytes.Buffer to reduce GC pressure.
type BytesBufPool struct {
	p       sync.Pool
	maxSize int
}

// NewBytesBufPool creates a new BytesBufPool.
// It uses a maxCap limit to prevent memory bloating from unusually large buffers.
func NewBytesBufPool(initSize int) *BytesBufPool {
	if initSize < 0 {
		initSize = 0
	}

	// Buffers larger than 64KB will not be returned to the pool to prevent memory bloat.
	const maxKeepSize = 64 * 1024

	return &BytesBufPool{
		maxSize: maxKeepSize,
		p: sync.Pool{
			New: func() interface{} {
				b := new(bytes.Buffer)
				if initSize > 0 {
					b.Grow(initSize)
				}
				return b
			},
		},
	}
}

// Get returns a *bytes.Buffer from the pool.
func (p *BytesBufPool) Get() *bytes.Buffer {
	return p.p.Get().(*bytes.Buffer)
}

// Release resets and returns the buffer to the pool.
// It discards buffers that have grown beyond maxSize to keep memory footprint low.
func (p *BytesBufPool) Release(b *bytes.Buffer) {
	if b == nil {
		return
	}

	// If the buffer grew too large (e.g., handling massive domain lists),
	// discard it so the GC can reclaim the memory.
	if b.Cap() > p.maxSize {
		return
	}

	b.Reset() // Resets length to 0 while keeping capacity.
	p.p.Put(b)
}
