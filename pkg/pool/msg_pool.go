package pool

import (
	"sync"

	"github.com/miekg/dns"
)

var msgPool = sync.Pool{
	New: func() interface{} {
		return new(dns.Msg)
	},
}

// GetMsg returns a *dns.Msg from the pool.
// The caller MUST call ReleaseMsg after use.
// The returned msg is NOT zeroed — caller must call Unpack or
// otherwise fully initialize it before use.
func GetMsg() *dns.Msg {
	return msgPool.Get().(*dns.Msg)
}

// ReleaseMsg returns a *dns.Msg to the pool.
// After calling ReleaseMsg, the caller MUST NOT access the msg.
func ReleaseMsg(m *dns.Msg) {
	// Zero the struct to avoid holding references to old data.
	*m = dns.Msg{}
	msgPool.Put(m)
}
