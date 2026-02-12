package cache

import (
	"context"
	"encoding/binary"
	"time"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/cache/mem_cache"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/pool"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"golang.org/x/sync/singleflight"
)

type Args struct {
	Size              int  `yaml:"size"`
	LazyCacheTTL      int  `yaml:"lazy_cache_ttl"`
	LazyCacheReplyTTL int  `yaml:"lazy_cache_reply_ttl"`
	CleanerInterval   *int `yaml:"cleaner_interval"`
}

type cachePlugin struct {
	*coremain.BP
	args         *Args
	backend      *mem_cache.MemCache
	lazyUpdateSF singleflight.Group
}

func (c *cachePlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	key, _ := dnsutils.GetMsgKey(q)
	if key == "" {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	packet, storedTime, offsets, count, lazyHit, ok := c.backend.Get(key)
	if ok {
		now := time.Now().Unix()
		// Acquire a buffer from the pool to avoid heap allocation
		buf := pool.GetBuf(len(packet))
		respRaw := buf.Bytes()[:len(packet)]
		copy(respRaw, packet)

		// 1. Patch Message ID (first 2 bytes)
		// DNS ID must match the current request
		binary.BigEndian.PutUint16(respRaw[:2], q.Id)

		// 2. Patch TTL logic - O(1) using pre-calculated offsets
		n := int(count)
		if lazyHit {
			// Use fixed stale TTL for lazy cache hits
			lTTL := uint32(c.args.LazyCacheReplyTTL)
			if lTTL == 0 {
				lTTL = 5
			}
			for i := 0; i < n; i++ {
				binary.BigEndian.PutUint32(respRaw[offsets[i]:], lTTL)
			}
			// Trigger background update for lazy cache
			c.doLazyUpdate(key, qCtx, next)
		} else {
			// Subtract elapsed time from original TTLs
			delta := now - storedTime
			if delta < 0 {
				delta = 0
			}
			elapsed := uint32(delta)
			for i := 0; i < n; i++ {
				off := offsets[i]
				oldTTL := binary.BigEndian.Uint32(respRaw[off : off+4])
				newTTL := uint32(1)
				if oldTTL > elapsed {
					newTTL = oldTTL - elapsed
				}
				binary.BigEndian.PutUint32(respRaw[off : off+4], newTTL)
			}
		}

		// 3. Handle Truncation & TC Bit (Specific to UDP Fast-path)
		// Since the transport layer is now "dumb", business logic must be handled here
		maxSize := 512
		if opt := q.IsEdns0(); opt != nil {
			maxSize = int(opt.UDPSize())
		}
		if maxSize < dns.MinMsgSize {
			maxSize = dns.MinMsgSize
		}

		isUDP := qCtx.ReqMeta().GetProtocol() == query_context.ProtocolUDP
		if isUDP && len(respRaw) > maxSize {
			respRaw = respRaw[:maxSize]
			if len(respRaw) >= 3 {
				// Set TC (Truncated) bit: Byte 2, Bit 1 (0x02)
				respRaw[2] |= 0x02 
			}
		}

		// ACTIVATE ZERO-UNPACK: Pass raw bytes directly to the transport layer
		// Do NOT call SetResponse(msg) after this, as it will clear RawR and releaseFunc
		qCtx.SetRawResponse(respRaw, func() {
			buf.Release() // Buffer is returned to the pool after the socket write is done
		})

		// Return nil to terminate the plugin chain immediately.
		// The server layer (UDP/TCP) will detect RawR and use the fast-path.
		return nil
	}

	// Cache Miss Path
	err := executable_seq.ExecChainNode(ctx, qCtx, next)
	if err == nil && qCtx.R() != nil {
		c.tryStore(key, qCtx.R())
	}
	return err
}

func (c *cachePlugin) tryStore(key string, r *dns.Msg) {
	// Skip caching if the response is truncated or an error (other than NXDOMAIN)
	if (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) || r.Truncated {
		return
	}

	packed, err := r.Pack()
	if err != nil {
		return
	}

	minTTL := dnsutils.GetMinimalTTL(r)
	if minTTL == 0 && len(r.Answer) > 0 {
		return
	}
	if minTTL == 0 {
		minTTL = 300
	}

	// Pre-extract TTL offsets to enable O(1) patching during cache hits
	offsets, count := dnsutils.ExtractTTLOffsets(packed)
	now := time.Now().Unix()
	expire := now + int64(minTTL)
	lazyExpire := expire + int64(c.args.LazyCacheTTL)

	c.backend.Store(key, packed, expire, lazyExpire, offsets, count)
}

func (c *cachePlugin) doLazyUpdate(key string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	// Prevent duplicate background updates for the same key
	c.lazyUpdateSF.DoChan(key, func() (interface{}, error) {
		defer c.lazyUpdateSF.Forget(key)
		lQCtx := qCtx.Copy()
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := executable_seq.ExecChainNode(bgCtx, lQCtx, next); err == nil && lQCtx.R() != nil {
			c.tryStore(key, lQCtx.R())
		}
		return nil, nil
	})
}
