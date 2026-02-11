package cache

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/singleflight"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/cache/mem_cache"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
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
	
	queryTotal, hitTotal, lazyHitTotal prometheus.Counter
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	a := args.(*Args)
	
	p := &cachePlugin{
		BP:      bp,
		args:    a,
		backend: mem_cache.NewMemCache(a.Size, time.Duration(30)*time.Second),
		queryTotal:   prometheus.NewCounter(prometheus.CounterOpts{Name: "cache_query_total"}),
		hitTotal:     prometheus.NewCounter(prometheus.CounterOpts{Name: "cache_hit_total"}),
		lazyHitTotal: prometheus.NewCounter(prometheus.CounterOpts{Name: "cache_lazy_hit_total"}),
	}
	bp.GetMetricsReg().MustRegister(p.queryTotal, p.hitTotal, p.lazyHitTotal)
	return p, nil
}

func (c *cachePlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	c.queryTotal.Inc()
	q := qCtx.Q()
	
	// Lấy Key đã bao gồm ECS (nếu có) từ dnsutils của ông
	key, _ := dnsutils.GetMsgKey(q)
	if key == "" { 
		return executable_seq.ExecChainNode(ctx, qCtx, next) 
	}

	packet, storedTime, lazyHit, ok := c.backend.Get(key)
	if ok {
		c.hitTotal.Inc()
		msg := new(dns.Msg)
		if err := msg.Unpack(packet); err != nil { 
			return executable_seq.ExecChainNode(ctx, qCtx, next) 
		}
		
		// Luôn phải vá ID của Request hiện tại
		msg.Id = q.Id

		if lazyHit {
			c.lazyHitTotal.Inc()
			// Trả IP cũ + ép TTL về giá trị nhỏ (5s)
			dnsutils.SetTTL(msg, uint32(c.args.LazyCacheReplyTTL))
			// Kích hoạt cập nhật ngầm
			c.doLazyUpdate(key, qCtx, next)
		} else {
			// Tính toán và trừ đi thời gian đã nằm trong cache
			elapsed := time.Now().Unix() - storedTime
			if elapsed > 0 {
				dnsutils.SubtractTTL(msg, uint32(elapsed))
			}
		}
		qCtx.SetResponse(msg)
		return nil
	}

	// Miss: Đi hỏi Upstream
	err := executable_seq.ExecChainNode(ctx, qCtx, next)
	if err == nil && qCtx.R() != nil {
		c.tryStore(key, qCtx.R())
	}
	return err
}

func (c *cachePlugin) tryStore(key string, r *dns.Msg) {
	// Không lưu gói tin lỗi hoặc bị cắt cụt
	if (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) || r.Truncated { 
		return 
	}
	
	packed, err := r.Pack()
	if err != nil { 
		return 
	}

	minTTL := dnsutils.GetMinimalTTL(r)
	if minTTL == 0 { 
		minTTL = 300 
	}

	now := time.Now().UnixNano()
	expire := now + (int64(minTTL) * 1e9)
	lazyExpire := expire + (int64(c.args.LazyCacheTTL) * 1e9)

	c.backend.Store(key, packed, expire, lazyExpire)
}

func (c *cachePlugin) doLazyUpdate(key string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	// Dùng Singleflight để tránh "bão" update cùng một domain
	c.lazyUpdateSF.DoChan(key, func() (interface{}, error) {
		defer c.lazyUpdateSF.Forget(key)
		
		lazyQCtx := qCtx.Copy()
		// Dùng context sạch vì Request chính có thể đã hoàn tất và bị cancel
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := executable_seq.ExecChainNode(bgCtx, lazyQCtx, next); err == nil && lazyQCtx.R() != nil {
			c.tryStore(key, lazyQCtx.R())
		}
		return nil, nil
	})
}

func (c *cachePlugin) Shutdown() error { 
	return c.backend.Close() 
}
