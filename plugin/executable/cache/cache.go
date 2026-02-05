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
	// Increased timeout to accommodate complex pipelines with retries or high latency upstreams
	defaultLazyUpdateTimeout = time.Second * 10
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
		c = mem_cache.NewMemCache(args.Size, 0)
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
	if len(msgKey) == 0 {
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

	if cachedResp != nil {
		c.hitTotal.Inc()
		cachedResp.Id = q.Id
		c.L().Debug("cache hit", qCtx.InfoField())
		qCtx.SetResponse(cachedResp)
		if c.whenHit != nil {
			return c.whenHit.Exec(ctx, qCtx, nil)
		}
		return nil
	}

	c.L().Debug("cache miss", qCtx.InfoField())
	err = executable_seq.ExecChainNode(ctx, qCtx, next)
	r := qCtx.R()

	// Pragmatic approach: Store response if it exists, even if execution returned an error (e.g., timeout).
	// This ensures cache is populated as long as a valid response was eventually received.
	if r != nil {
		if err := c.tryStoreMsg(msgKey, r); err != nil {
			c.L().Debug("cache store failed", qCtx.InfoField(), zap.Error(err))
		}
	}
	return err
}

func (c *cachePlugin) getMsgKey(q *dns.Msg) (string, error) {
	isSimpleQuery := len(q.Question) == 1 && len(q.Answer) == 0 && len(q.Ns) == 0 && len(q.Extra) == 0
	if isSimpleQuery || c.args.CacheEverything {
		return dnsutils.GetMsgKey(q, 0)
	}
	
	// When cache_everything is false, cache using only Question section (domain + type)
	// This increases cache hit rate by ignoring Answer/Ns/Extra metadata
	if len(q.Question) == 1 {
		simpleQ := *q
		simpleQ.Answer = nil
		simpleQ.Ns = nil
		simpleQ.Extra = nil
		msgKey, err := dnsutils.GetMsgKey(&simpleQ, 0)
		if err != nil {
			return "", fmt.Errorf("failed to get msg key, %w", err)
		}
		return msgKey, nil
	}
	
	return "", nil
}

func (c *cachePlugin) lookupCache(msgKey string) (r *dns.Msg, lazyHit bool, err error) {
	v, storedTime, _ := c.backend.Get(msgKey)
	if v != nil {
		if c.args.CompressResp {
			decodeLen, err := snappy.DecodedLen(v)
			if err != nil {
				return nil, false, fmt.Errorf("snappy decode err: %w", err)
			}
			decompressBuf := pool.GetBuf(decodeLen)
			defer decompressBuf.Release()

			decoded, err := snappy.Decode(decompressBuf.Bytes(), v)
			if err != nil {
				return nil, false, fmt.Errorf("snappy decode err: %w", err)
			}
			// Copy data to an independent slice before buffer is released back to pool
			v = append([]byte(nil), decoded...)
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

		if storedTime.Add(msgTTL).After(time.Now()) {
			dnsutils.SubtractTTL(r, uint32(time.Since(storedTime).Seconds()))
			return r, false, nil
		}

		if c.args.LazyCacheTTL > 0 {
			dnsutils.SetTTL(r, uint32(c.args.LazyCacheReplyTTL))
			return r, true, nil
		}
	}
	return nil, false, nil
}

// doLazyUpdate starts a background goroutine to update the cache asynchronously.
// It uses singleflight to deduplicate concurrent updates for the same msgKey.
// The lazy update uses a detached context to prevent cancellation propagation from the original request,
// while qCtx.Copy() preserves all necessary query metadata (client IP, ECS settings, etc.).
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

		// Try storing response even if execution failed (e.g., deadline exceeded),
		// provided a response object was populated in qCtx.
		r := lazyQCtx.R()
		if r != nil {
			_ = c.tryStoreMsg(msgKey, r)
		}
		c.L().Debug("lazy cache updated", lazyQCtx.InfoField())
		return nil, nil
	}

	c.lazyUpdateSF.DoChan(msgKey, lazyUpdateFunc)
}

func (c *cachePlugin) tryStoreMsg(key string, r *dns.Msg) error {
	if r.Truncated || (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) {
		return nil
	}

	v, err := r.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack response msg, %w", err)
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

	if c.args.CompressResp {
		compressBuf := pool.GetBuf(snappy.MaxEncodedLen(len(v)))
		defer compressBuf.Release()

		compressed := snappy.Encode(compressBuf.Bytes(), v)
		// Deep copy to ensure data stability after buffer release
		v = append([]byte(nil), compressed...)
	}

	c.backend.Store(key, v, now, expirationTime)
	return nil
}

func (c *cachePlugin) Shutdown() error {
	return c.backend.Close()
}
