package cache

import "io"

type Backend interface {
	// Get retrieves cached packet.
	// Returns:
	//   - packet: raw DNS wire format (may be compressed)
	//   - storedTime: Unix timestamp (seconds) when stored
	//   - lazyHit: true if entry is stale but within lazy window
	//   - ok: false if not found or fully expired
	Get(key string) (packet []byte, storedTime int64, lazyHit bool, ok bool)

	// Store caches a DNS packet with dual expiration.
	// Params:
	//   - packet: raw DNS wire format (caller's buffer, will be copied)
	//   - expire: Unix nano when DNS TTL expires (fresh → stale)
	//   - lazyExpire: Unix nano when entry should be evicted (stale → deleted)
	// If lazyExpire <= expire, lazy mode is disabled.
	Store(key string, packet []byte, expire, lazyExpire int64)

	Len() int

	io.Closer
}
