package cache

import "io"

type Backend interface {
	// Get returns cached packet and precomputed TTL metadata.
	// Returns:
	//   packet: raw DNS wire format
	//   storedTime: Unix timestamp in SECONDS
	//   offsets: fixed array of TTL field positions
	//   count: number of TTL fields
	//   lazyHit: true if stale but within lazy window
	//   ok: false if not found or fully expired
	Get(key string) (packet []byte, storedTime int64, offsets [8]uint16, count uint8, lazyHit bool, ok bool)

	// Store caches a DNS packet with precomputed TTL metadata.
	// Params:
	//   packet: raw DNS wire format
	//   expire: Unix nano when DNS TTL expires
	//   lazyExpire: Unix nano when entry should be evicted
	//   offsets: precomputed TTL field positions
	//   count: number of TTL fields
	Store(key string, packet []byte, expire, lazyExpire int64, offsets [8]uint16, count uint8)

	Len() int

	io.Closer
}
