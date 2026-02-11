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

type cachePlugin struct {
	*coremain.BP
	args         *Args
	backend      *mem_cache.MemCache // Static dispatch for performance
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
		buf := pool.GetBuf(len(packet))
		respRaw := buf.Bytes()[:len(packet)]
		copy(respRaw, packet)

		// Patch Message ID (first 2 bytes)
		binary.BigEndian.PutUint16(respRaw[:2], q.Id)

		n := int(count)
		if lazyHit {
			// Handle stale record with Lazy TTL
			lTTL := uint32(c.args.LazyCacheReplyTTL)
			if lTTL == 0 {
				lTTL = 5
			}
			for i := 0; i < n; i++ {
				binary.BigEndian.PutUint32(respRaw[offsets[i]:], lTTL)
			}
			// Trigger background update
			c.doLazyUpdate(key, qCtx, next)
		} else {
			// Patch TTL by subtracting elapsed time
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

		// Final step: Unpack to dns.Msg as required by current framework
		// TODO: Implement SetRawResponse support in framework to skip Unpack
		msg := new(dns.Msg)
		err := msg.Unpack(respRaw)
		buf.Release()

		if err == nil {
			qCtx.SetResponse(msg)
			return nil
		}
	}

	// Cache Miss Path
	err := executable_seq.ExecChainNode(ctx, qCtx, next)
	if err == nil && qCtx.R() != nil {
		c.tryStore(key, qCtx.R())
	}
	return err
}

func (c *cachePlugin) tryStore(key string, r *dns.Msg) {
	// Only cache successful responses or NXDOMAIN
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

	// Precompute TTL offsets for fast patching on hit
	offsets, count := dnsutils.ExtractTTLOffsets(packed)
	now := time.Now().Unix()
	
	expire := now + int64(minTTL)
	lazyExpire := expire + int64(c.args.LazyCacheTTL)

	c.backend.Store(key, packed, expire, lazyExpire, offsets, count)
}

func (c *cachePlugin) doLazyUpdate(key string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	// Use singleflight to prevent cache stampede for the same key
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
