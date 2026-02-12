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

const PluginType = "cache"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*cachePlugin)(nil)

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

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	arg := args.(*Args)
	interval := 60 * time.Second
	if arg.CleanerInterval != nil && *arg.CleanerInterval > 0 {
		interval = time.Duration(*arg.CleanerInterval) * time.Second
	}

	return &cachePlugin{
		BP:      bp,
		args:    arg,
		backend: mem_cache.NewMemCache(arg.Size, interval),
	}, nil
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

		binary.BigEndian.PutUint16(respRaw[:2], q.Id)

		n := int(count)
		if lazyHit {
			lTTL := uint32(c.args.LazyCacheReplyTTL)
			if lTTL == 0 {
				lTTL = 5
			}
			for i := 0; i < n; i++ {
				binary.BigEndian.PutUint32(respRaw[offsets[i]:], lTTL)
			}
			c.doLazyUpdate(key, qCtx, next)
		} else {
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

		maxSize := 512
		if opt := q.IsEdns0(); opt != nil {
			maxSize = int(opt.UDPSize())
		}
		if maxSize < dns.MinMsgSize {
			maxSize = dns.MinMsgSize
		}

		if qCtx.ReqMeta().GetProtocol() == query_context.ProtocolUDP && len(respRaw) > maxSize {
			respRaw = respRaw[:maxSize]
			if len(respRaw) >= 3 {
				respRaw[2] |= 0x02
			}
		}

		qCtx.SetRawResponse(respRaw, func() {
			buf.Release()
		})
		return nil
	}

	err := executable_seq.ExecChainNode(ctx, qCtx, next)
	if err == nil && qCtx.R() != nil {
		c.tryStore(key, qCtx.R())
	}
	return err
}

func (c *cachePlugin) tryStore(key string, r *dns.Msg) {
	if (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) || r.Truncated {
		return
	}
	packed, _ := r.Pack()
	minTTL := dnsutils.GetMinimalTTL(r)
	if minTTL == 0 {
		minTTL = 300
	}

	offsets, count := dnsutils.ExtractTTLOffsets(packed)
	now := time.Now().Unix()
	expire := now + int64(minTTL)
	lazyExpire := expire + int64(c.args.LazyCacheTTL)

	c.backend.Store(key, packed, expire, lazyExpire, offsets, count)
}

func (c *cachePlugin) doLazyUpdate(key string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	lQCtx := qCtx.Copy()
	c.lazyUpdateSF.DoChan(key, func() (interface{}, error) {
		defer c.lazyUpdateSF.Forget(key)
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := executable_seq.ExecChainNode(bgCtx, lQCtx, next); err == nil && lQCtx.R() != nil {
			c.tryStore(key, lQCtx.R())
		}
		return nil, nil
	})
}

func (c *cachePlugin) Shutdown() error {
	if c.backend != nil {
		return c.backend.Close()
	}
	return nil
}
