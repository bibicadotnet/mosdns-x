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
		
		// Acquire a buffer from the pool to minimize heap allocations
		buf := pool.GetBuf(len(packet))
		respRaw := buf.Bytes()[:len(packet)]
		copy(respRaw, packet)

		// 1. Patch Message ID (first 2 bytes) to match the current query
		binary.BigEndian.PutUint16(respRaw[:2], q.Id)

		// 2. TTL (Time To Live) patching using pre-calculated offsets
		n := int(count)
		if lazyHit {
			// Apply fixed stale TTL for lazy cache responses
			lTTL := uint32(c.args.LazyCacheReplyTTL)
			if lTTL == 0 {
				lTTL = 5
			}
			for i := 0; i < n; i++ {
				binary.BigEndian.PutUint32(respRaw[offsets[i]:], lTTL)
			}
			
			// Snapshot the context on the main goroutine to prevent data races
			// before triggering the background asynchronous update
			c.doLazyUpdate(key, qCtx, next)
		} else {
			// Calculate effective TTL by subtracting elapsed time since storage
			elapsed := uint32(now - storedTime)
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

		// 3. Handle DNS message truncation for UDP protocol
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
				// Set TC (Truncated) bit in the DNS Header (Byte 2, Bit 1)
				respRaw[2] |= 0x02 
			}
		}

		// Activate Zero-Unpack fast path by passing raw bytes to the transport layer.
		// The release callback ensures the buffer returns to the pool after the socket write.
		qCtx.SetRawResponse(respRaw, func() {
			buf.Release() 
		})

		// Terminate execution chain and return immediately to bypass downstream plugins
		return nil
	}

	// Cache Miss: proceed with the execution chain and attempt to store the result
	err := executable_seq.ExecChainNode(ctx, qCtx, next)
	if err == nil && qCtx.R() != nil {
		c.tryStore(key, qCtx.R())
	}
	return err
}

func (c *cachePlugin) tryStore(key string, r *dns.Msg) {
	// Do not cache truncated responses or errors (excluding NXDOMAIN/NODATA)
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

	// Extract TTL offsets for Answer and Authority sections to enable O(1) patching
	offsets, count := dnsutils.ExtractTTLOffsets(packed)
	now := time.Now().Unix()
	expire := now + int64(minTTL)
	lazyExpire := expire + int64(c.args.LazyCacheTTL)

	c.backend.Store(key, packed, expire, lazyExpire, offsets, count)
}

func (c *cachePlugin) doLazyUpdate(key string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	// Deep copy logical state to isolate the background task from the current request.
	// Note: rawR and releaseFunc are not copied, preventing buffer lifetime issues.
	lQCtx := qCtx.Copy()

	c.lazyUpdateSF.DoChan(key, func() (interface{}, error) {
		defer c.lazyUpdateSF.Forget(key)
		
		// Establish a dedicated timeout for the background refresh task
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Re-execute the downstream chain to update the cache with fresh data
		if err := executable_seq.ExecChainNode(bgCtx, lQCtx, next); err == nil && lQCtx.R() != nil {
			c.tryStore(key, lQCtx.R())
		}
		return nil, nil
	})
}
