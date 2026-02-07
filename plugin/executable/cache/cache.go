package cache

import (
	"context"
	"encoding/binary"
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

const PluginType = "cache"

const (
	cacheMagic               = 0x4D43 // "MC"
	cacheVersion             = 0x01
	defaultLazyUpdateTimeout = 10 * time.Second
	defaultEmptyAnswerTTL    = 300 * time.Second
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

	whenHit executable_seq.Executable
	backend cache.Backend

	sf singleflight.Group

	queryTotal   prometheus.Counter
	hitTotal     prometheus.Counter
	lazyHitTotal prometheus.Counter
	size         prometheus.GaugeFunc
}

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
	coremain.RegNewPersetPluginFunc("_default_cache", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newCachePlugin(bp, &Args{})
	})
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	return newCachePlugin(bp, args.(*Args))
}

func newCachePlugin(bp *coremain.BP, args *Args) (*cachePlugin, error) {
	var backend cache.Backend

	if args.Redis != "" {
		opt, err := redis.ParseURL(args.Redis)
		if err != nil {
			return nil, err
		}
		opt.MaxRetries = -1
		r := redis.NewClient(opt)
		backend, err = redis_cache.NewRedisCache(redis_cache.RedisCacheOpts{
			Client:        r,
			ClientCloser:  r,
			ClientTimeout: time.Duration(args.RedisTimeout) * time.Millisecond,
			Logger:        bp.L(),
		})
		if err != nil {
			return nil, err
		}
	} else {
		backend = mem_cache.NewMemCache(args.Size, 0)
	}

	if args.LazyCacheReplyTTL <= 0 {
		args.LazyCacheReplyTTL = 5
	}

	var whenHit executable_seq.Executable
	if args.WhenHit != "" {
		whenHit = bp.M().GetExecutables()[args.WhenHit]
		if whenHit == nil {
			return nil, fmt.Errorf("cannot find executable %s", args.WhenHit)
		}
	}

	p := &cachePlugin{
		BP:      bp,
		args:    args,
		whenHit: whenHit,
		backend: backend,

		queryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "query_total",
			Help: "Total queries eligible for caching",
		}),
		hitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hit_total",
			Help: "Total fresh hits",
		}),
		lazyHitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "lazy_hit_total",
			Help: "Total stale hits (lazy)",
		}),
		size: prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{Name: "cache_size"},
			func() float64 { return float64(backend.Len()) },
		),
	}

	bp.GetMetricsReg().MustRegister(p.queryTotal, p.hitTotal, p.lazyHitTotal, p.size)

	return p, nil
}

func (c *cachePlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	key, err := c.buildKey(q)
	if err != nil || key == "" {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	c.queryTotal.Inc()

	msg, lazy, err := c.lookup(key)
	if err != nil {
		c.L().Debug("lookup cache internal error", zap.Error(err))
	}

	if msg != nil {
		msg.Id = q.Id
		qCtx.SetResponse(msg)
		c.hitTotal.Inc()

		if lazy {
			c.lazyHitTotal.Inc()
			c.L().Debug("lazy hit", qCtx.InfoField(), zap.String("key", key))
			c.triggerLazyUpdate(key, qCtx, next)
		} else {
			c.L().Debug("hit", qCtx.InfoField())
		}

		if c.whenHit != nil {
			return c.whenHit.Exec(ctx, qCtx, nil)
		}
		return nil
	}

	c.L().Debug("miss", qCtx.InfoField())
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	if r := qCtx.R(); r != nil {
		_ = c.store(key, r)
	}

	return nil
}

func (c *cachePlugin) buildKey(q *dns.Msg) (string, error) {
	if c.args.CacheEverything {
		return dnsutils.GetMsgKey(q, 0)
	}

	if len(q.Question) != 1 {
		return "", nil
	}

	// Hot-path: Direct key for simple queries (No struct copy)
	if len(q.Answer) == 0 && len(q.Ns) == 0 && len(q.Extra) == 0 {
		return dnsutils.GetMsgKey(q, 0)
	}

	// Normalize key for domain + type only if metadata exists (Copy only when needed)
	simpleQ := *q
	simpleQ.Answer, simpleQ.Ns, simpleQ.Extra = nil, nil, nil
	return dnsutils.GetMsgKey(&simpleQ, 0)
}

func (c *cachePlugin) lookup(key string) (msg *dns.Msg, lazy bool, err error) {
	v, stored, _ := c.backend.Get(key)
	if v == nil {
		return nil, false, nil
	}

	var ttl uint32
	var payload []byte
	isNewFormat := false

	// Format Detection [Magic: 2B][Version: 1B]
	if len(v) >= 7 && binary.BigEndian.Uint16(v[0:2]) == cacheMagic {
		if v[2] == cacheVersion {
			ttl = binary.BigEndian.Uint32(v[3:7])
			payload = v[7:]
			isNewFormat = true
		}
	}

	if isNewFormat {
		if len(payload) == 0 {
			return nil, false, nil
		}
		if c.args.CompressResp {
			decLen, err := snappy.DecodedLen(payload)
			if err != nil || decLen <= 0 || decLen > dns.MaxMsgSize {
				return nil, false, nil // Silent drop/Miss
			}
			decBuf := pool.GetBuf(decLen)
			defer decBuf.Release()
			payload, err = snappy.Decode(decBuf.Bytes()[:0], payload)
			if err != nil {
				return nil, false, nil
			}
		}
		msg = new(dns.Msg)
		if err := msg.Unpack(payload); err != nil {
			return nil, false, nil
		}
	} else {
		// Legacy Fallback with Decompression support
		payload = v
		if c.args.CompressResp {
			decLen, err := snappy.DecodedLen(payload)
			if err != nil || decLen <= 0 || decLen > dns.MaxMsgSize {
				return nil, false, nil
			}
			decBuf := pool.GetBuf(decLen)
			defer decBuf.Release()
			payload, err = snappy.Decode(decBuf.Bytes()[:0], payload)
			if err != nil {
				return nil, false, nil
			}
		}
		msg = new(dns.Msg)
		if err := msg.Unpack(payload); err != nil {
			return nil, false, nil
		}
		if len(msg.Answer) == 0 {
			ttl = uint32(defaultEmptyAnswerTTL / time.Second)
		} else {
			ttl = dnsutils.GetMinimalTTL(msg)
		}
	}

	// Unified TTL check (Fresh vs Stale)
	now := time.Now()
	elapsed := uint32(now.Sub(stored).Seconds())

	if elapsed < ttl {
		dnsutils.SubtractTTL(msg, elapsed)
		return msg, false, nil
	}

	if c.args.LazyCacheTTL > 0 && elapsed < (ttl+uint32(c.args.LazyCacheTTL)) {
		dnsutils.SetTTL(msg, uint32(c.args.LazyCacheReplyTTL))
		return msg, true, nil
	}

	return nil, false, nil
}

func (c *cachePlugin) triggerLazyUpdate(key string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	go func() {
		_, _, _ = c.sf.Do(key, func() (any, error) {
			c.L().Debug("lazy update start", zap.String("key", key))
			lazyQCtx := qCtx.Copy()
			lazyQCtx.SetResponse(nil)
			ctx, cancel := context.WithTimeout(context.Background(), defaultLazyUpdateTimeout)
			defer cancel()
			if err := executable_seq.ExecChainNode(ctx, lazyQCtx, next); err != nil {
				c.L().Warn("lazy update failed", zap.Error(err), zap.String("key", key))
				return nil, err
			}
			if r := lazyQCtx.R(); r != nil {
				_ = c.store(key, r)
				c.L().Debug("lazy update success", zap.String("key", key))
			}
			return nil, nil
		})
	}()
}

func (c *cachePlugin) store(key string, r *dns.Msg) error {
	if r.Truncated || (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) {
		return nil
	}

	var ttl uint32
	if len(r.Answer) == 0 {
		ttl = uint32(defaultEmptyAnswerTTL / time.Second)
	} else {
		ttl = dnsutils.GetMinimalTTL(r)
	}

	if ttl == 0 {
		return nil
	}
	
	r.Compress = true
	raw, err := r.Pack()
	if err != nil {
		return err
	}

	var finalPayload []byte
	var compBuf *pool.Buffer

	if c.args.CompressResp {
		compBuf = pool.GetBuf(snappy.MaxEncodedLen(len(raw)))
		finalPayload = snappy.Encode(compBuf.Bytes()[:0], raw)
	} else {
		finalPayload = raw
	}

	bufWrapper := pool.GetBuf(7 + len(finalPayload))
	defer bufWrapper.Release()
	if compBuf != nil {
		defer compBuf.Release()
	}

	data := bufWrapper.Bytes()
	binary.BigEndian.PutUint16(data[0:2], uint16(cacheMagic))
	data[2] = cacheVersion
	binary.BigEndian.PutUint32(data[3:7], ttl)
	copy(data[7:], finalPayload)

	now := time.Now()
	storageTTL := time.Duration(ttl) * time.Second
	if c.args.LazyCacheTTL > 0 {
		storageTTL += time.Duration(c.args.LazyCacheTTL) * time.Second
	}

	c.backend.Store(key, data, now, now.Add(storageTTL))
	return nil
}

func (c *cachePlugin) Shutdown() error {
	return c.backend.Close()
}
