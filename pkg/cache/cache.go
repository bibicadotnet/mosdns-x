package cache

import "io"

type Backend interface {
	// Get returns cached packet.
	// Returns:
	//   packet: raw DNS wire format
	//   storedTime: Unix timestamp in SECONDS (for TTL subtraction)
	//   lazyHit: true if stale but within lazy window
	//   ok: false if not found or fully expired
	Get(key string) (packet []byte, storedTime int64, lazyHit bool, ok bool)

	// Store caches a DNS packet with dual expiration.
	// Params:
	//   packet: raw DNS wire format (will be copied by backend)
	//   expire: Unix timestamp in NANOSECONDS when DNS TTL expires
	//   lazyExpire: Unix timestamp in NANOSECONDS when entry should be evicted
	Store(key string, packet []byte, expire, lazyExpire int64)

	Len() int

	io.Closer
}
