package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang/snappy"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/cache"
	"github.com/pmkol/mosdns-x/pkg/cache/mem_cache"
	"github.com/pmkol/mosdns-x/pkg/cache/redis_cache"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/pool"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const (
	PluginType = "cache"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })

	coremain.RegNewPersetPluginFunc("_default_cache", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newCachePlugin(bp, &Args{})
	})
}

const (
	defaultLazyUpdateTimeout = time.Second * 5
	defaultEmptyAnswerTTL    = time.Second * 300
)

var _ coremain.ExecutablePlugin = (*cachePlugin)(nil)

type Args struct {
	Size              int    `yaml:"size"`
	Redis             string `yaml:"redis"`
	RedisTimeout      int    `yaml:"redis_timeout"`
	LazyCacheTTL      int    `yaml:"lazy_cache_ttl"`
	LazyCacheReplyTTL int    `yaml:"lazy_cache_reply_ttl"`
	CacheEverything   bool   `yaml:"cache_everything"`
	CompressResp      bool   `yaml:"compress_resp"`
	WhenHit           string `yaml:"when_hit"`
	CleanerInterval   *int   `yaml:"cleaner_interval"`
}

type cachePlugin struct {
	*coremain.BP
	args *Args

	whenHit      executable_seq.Executable
	backend      cache.Backend
	lazyUpdateSF singleflight.Group

	queryTotal   prometheus.Counter
	hitTotal     prometheus.Counter
	lazyHitTotal prometheus.Counter
	size         prometheus.GaugeFunc
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newCachePlugin(bp, args.(*Args))
}

func newCachePlugin(bp *coremain.BP, args *Args) (*cachePlugin, error) {
	var c cache.Backend
	if len(args.Redis) != 0 {
		opt, err := redis.ParseURL(args.Redis)
		if err != nil {
			return nil, fmt.Errorf("invalid redis url, %w", err)
		}
		opt.MaxRetries = -1
		r := redis.NewClient(opt)
		rcOpts := redis_cache.RedisCacheOpts{
			Client:        r,
			ClientCloser:  r,
			ClientTimeout: time.Duration(args.RedisTimeout) * time.Millisecond,
			Logger:        bp.L(),
		}
		rc, err := redis_cache.NewRedisCache(rcOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to init redis cache, %w", err)
		}
		c = rc
	} else {
		cleanerSec := 60
		if args.CleanerInterval != nil {
			cleanerSec = *args.CleanerInterval
		}

		var interval time.Duration
		if cleanerSec > 0 {
			interval = time.Duration(cleanerSec) * time.Second
		}

		c = mem_cache.NewMemCache(args.Size, interval)
	}

	if args.LazyCacheReplyTTL <= 0 {
		args.LazyCacheReplyTTL = 5
	}

	var whenHit executable_seq.Executable
	if tag := args.WhenHit; len(tag) > 0 {
		m := bp.M().GetExecutables()
		whenHit = m[tag]
		if whenHit == nil {
			return nil, fmt.Errorf("cannot find executable %s", tag)
		}
	}

	p := &cachePlugin{
		BP:      bp,
		args:    args,
		whenHit: whenHit,
		backend: c,

		queryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "query_total",
			Help: "The total number of processed queries",
		}),
		hitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hit_total",
			Help: "The total number of queries that hit the cache",
		}),
		lazyHitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lazy_hit_total",
			Help: "The total number of queries that hit the expired cache",
		}),
		size: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "cache_size",
			Help: "Current cache size in records",
		}, func() float64 {
			return float64(c.Len())
		}),
	}
	bp.GetMetricsReg().MustRegister(p.queryTotal, p.hitTotal, p.lazyHitTotal, p.size)
	return p, nil
}

func (c *cachePlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	c.queryTotal.Inc()
	q := qCtx.Q()

	msgKey, err := c.getMsgKey(q)
	if err != nil {
		c.L().Error("get msg key", qCtx.InfoField(), zap.Error(err))
	}
	if len(msgKey) == 0 { // skip cache
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	cachedResp, lazyHit, err := c.lookupCache(msgKey)
	if err != nil {
		c.L().Error("lookup cache", qCtx.InfoField(), zap.Error(err))
	}
	if lazyHit {
		c.lazyHitTotal.Inc()
		c.doLazyUpdate(msgKey, qCtx, next)
	}
	if cachedResp != nil { // cache hit
		c.hitTotal.Inc()
		cachedResp.Id = q.Id // change msg id
		c.L().Debug("cache hit", qCtx.InfoField())
		qCtx.SetResponse(cachedResp)
		if c.whenHit != nil {
			return c.whenHit.Exec(ctx, qCtx, nil)
		}
		return nil
	}

	// cache miss, run the entry and try to store its response.
	c.L().Debug("cache miss", qCtx.InfoField())
	err = executable_seq.ExecChainNode(ctx, qCtx, next)
	r := qCtx.R()
	if r != nil {
		if err := c.tryStoreMsg(msgKey, r); err != nil {
			c.L().Error("cache store", qCtx.InfoField(), zap.Error(err))
		}
	}
	return err
}

func (c *cachePlugin) getMsgKey(q *dns.Msg) (string, error) {
	if len(q.Question) != 1 {
		return "", nil
	}
	return dnsutils.GetMsgKey(q, 0)
}

func (c *cachePlugin) lookupCache(msgKey string) (r *dns.Msg, lazyHit bool, err error) {
	v, storedTime, _ := c.backend.Get(msgKey)
	if v != nil {
		if c.args.CompressResp {
			decodeLen, err := snappy.DecodedLen(v)
			if err != nil {
				return nil, false, fmt.Errorf("snappy decode err: %w", err)
			}
			if decodeLen > dns.MaxMsgSize {
				return nil, false, fmt.Errorf("invalid snappy data, not a dns msg, data len: %d", decodeLen)
			}
			decompressBuf := pool.GetBuf(decodeLen)
			defer decompressBuf.Release()
			v, err = snappy.Decode(decompressBuf.Bytes(), v)
			if err != nil {
				return nil, false, fmt.Errorf("snappy decode err: %w", err)
			}
		}
		r = new(dns.Msg)
		if err := r.Unpack(v); err != nil {
			return nil, false, fmt.Errorf("failed to unpack cached data, %w", err)
		}

		var msgTTL time.Duration
		if len(r.Answer) == 0 {
			msgTTL = defaultEmptyAnswerTTL
		} else {
			msgTTL = time.Duration(dnsutils.GetMinimalTTL(r)) * time.Second
		}

		now := time.Now()
		elapsed := now.Sub(storedTime)
		if storedTime.Add(msgTTL).After(now) {
			if elapsed > 0 {
				dnsutils.SubtractTTL(r, uint32(elapsed.Seconds()))
			}
			return r, false, nil
		}

		if c.args.LazyCacheTTL > 0 {
			dnsutils.SetTTL(r, uint32(c.args.LazyCacheReplyTTL))
			return r, true, nil
		}
	}
	return nil, false, nil
}

func (c *cachePlugin) doLazyUpdate(msgKey string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	lazyQCtx := qCtx.Copy()
	lazyUpdateFunc := func() (interface{}, error) {
		c.L().Debug("start lazy cache update", lazyQCtx.InfoField())
		defer c.lazyUpdateSF.Forget(msgKey)
		lazyCtx, cancel := context.WithTimeout(context.Background(), defaultLazyUpdateTimeout)
		defer cancel()

		err := executable_seq.ExecChainNode(lazyCtx, lazyQCtx, next)
		if err != nil {
			c.L().Warn("failed to update lazy cache", lazyQCtx.InfoField(), zap.Error(err))
		}

		r := lazyQCtx.R()
		if r != nil {
			if err := c.tryStoreMsg(msgKey, r); err != nil {
				c.L().Error("cache store", qCtx.InfoField(), zap.Error(err))
			}
		}
		c.L().Debug("lazy cache updated", lazyQCtx.InfoField())
		return nil, nil
	}
	c.lazyUpdateSF.DoChan(msgKey, lazyUpdateFunc)
}

func (c *cachePlugin) tryStoreMsg(key string, r *dns.Msg) error {
	if (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) || r.Truncated {
		return nil
	}

	var v []byte
	if c.args.CompressResp {
		// Use pooled buffer for temporary packing to eliminate heap allocation from r.Pack()
		wireMsg, buf, err := pool.PackBuffer(r)
		if err != nil {
			return fmt.Errorf("failed to pack response msg, %w", err)
		}
		
		// Direct heap allocation for the compressed result to ensure data safety
		// in asynchronous backends (e.g., Redis).
		compressed := make([]byte, snappy.MaxEncodedLen(len(wireMsg)))
		v = snappy.Encode(compressed, wireMsg)
		
		// Immediately release pooled buffer after compression
		buf.Release()
	} else {
		// No compression: standard Pack() creates its own owned slice, which is safe.
		var err error
		v, err = r.Pack()
		if err != nil {
			return fmt.Errorf("failed to pack response msg, %w", err)
		}
	}

	now := time.Now()
	var expirationTime time.Time
	if c.args.LazyCacheTTL > 0 {
		expirationTime = now.Add(time.Duration(c.args.LazyCacheTTL) * time.Second)
	} else {
		minTTL := dnsutils.GetMinimalTTL(r)
		if minTTL == 0 {
			return nil
		}
		expirationTime = now.Add(time.Duration(minTTL) * time.Second)
	}

	c.backend.Store(key, v, now, expirationTime)
	return nil
}

func (c *cachePlugin) Shutdown() error {
	return c.backend.Close()
}
