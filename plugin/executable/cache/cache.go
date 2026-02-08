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

const (
	PluginType               = "cache"
	cacheMagic               = 0x4D43 // "MC"
	cacheVersion             = 0x01
	defaultLazyUpdateTimeout = 10 * time.Second
	defaultEmptyAnswerTTL    = 300 * time.Second
)

type Args struct {
	Size              int    `yaml:"size"`
	Redis             string `yaml:"redis"`
	RedisTimeout      int    `yaml:"redis_timeout"`
	LazyCacheTTL      int    `yaml:"lazy_cache_ttl"`
	LazyCacheReplyTTL int    `yaml:"lazy_cache_reply_ttl"`
	CacheEverything   bool   `yaml:"cache_everything"`
	CompressResp      bool   `yaml:"compress_resp"`
	WhenHit           string `yaml:"when_hit"`
	// Use pointer to distinguish between "not set" (nil) and "set to 0" (0)
	CleanerInterval   *int   `yaml:"cleaner_interval"`
}

type cachePlugin struct {
	*coremain.BP
	args *Args

	whenHit executable_seq.Executable
	backend cache.Backend
	sf      singleflight.Group

	queryTotal   prometheus.Counter
	hitTotal     prometheus.Counter
	lazyHitTotal prometheus.Counter
	size         prometheus.GaugeFunc
}

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	a := args.(*Args)
	var backend cache.Backend
	var err error

	if a.Redis != "" {
		opt, _ := redis.ParseURL(a.Redis)
		opt.MaxRetries = -1
		r := redis.NewClient(opt)
		backend, err = redis_cache.NewRedisCache(redis_cache.RedisCacheOpts{
			Client:        r,
			ClientCloser:  r,
			ClientTimeout: time.Duration(a.RedisTimeout) * time.Millisecond,
			Logger:        bp.L(),
		})
		if err != nil {
			return nil, err
		}
	} else {
		// Logic: Default to 60s if not set (nil). If set to 0, it stays 0 (disabled).
		cleanerSec := 60
		if a.CleanerInterval != nil {
			cleanerSec = *a.CleanerInterval
		}

		var interval time.Duration
		if cleanerSec > 0 {
			interval = time.Duration(cleanerSec) * time.Second
		}

		backend = mem_cache.NewMemCache(a.Size, interval)
	}

	if a.LazyCacheReplyTTL <= 0 { a.LazyCacheReplyTTL = 5 }
	if a.LazyCacheTTL < 0 { a.LazyCacheTTL = 0 }

	var whenHit executable_seq.Executable
	if a.WhenHit != "" {
		if whenHit = bp.M().GetExecutables()[a.WhenHit]; whenHit == nil {
			return nil, fmt.Errorf("executable %s not found", a.WhenHit)
		}
	}

	p := &cachePlugin{
		BP: bp, args: a, whenHit: whenHit, backend: backend,
		queryTotal:   prometheus.NewCounter(prometheus.CounterOpts{Name: "query_total"}),
		hitTotal:     prometheus.NewCounter(prometheus.CounterOpts{Name: "hit_total"}),
		lazyHitTotal: prometheus.NewCounter(prometheus.CounterOpts{Name: "lazy_hit_total"}),
		size:         prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "cache_size"}, func() float64 { return float64(backend.Len()) }),
	}
	bp.GetMetricsReg().MustRegister(p.queryTotal, p.hitTotal, p.lazyHitTotal, p.size)
	return p, nil
}

func (c *cachePlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	key, _ := c.buildKey(q)
	if key == "" {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	c.queryTotal.Inc()
	msg, lazy, err := c.lookup(key)
	if err != nil {
		c.L().Debug("lookup cache internal error", zap.Error(err), zap.String("key", key))
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
		c.store(key, r)
	}

	return nil
}

func (c *cachePlugin) buildKey(q *dns.Msg) (string, error) {
	if len(q.Question) != 1 { return "", nil }
	if c.args.CacheEverything {
		return dnsutils.GetMsgKey(q, 0)
	}
	return dnsutils.GetMsgKeyWithTag(q, ""), nil
}

func (c *cachePlugin) lookup(key string) (*dns.Msg, bool, error) {
	v, stored, _ := c.backend.Get(key)
	if v == nil { return nil, false, nil }

	var ttl uint32
	var payload []byte
	elapsed := uint32(time.Since(stored).Seconds())

	// Fast path: Header validation
	if len(v) >= 7 && binary.BigEndian.Uint16(v[0:2]) == cacheMagic && v[2] == cacheVersion {
		ttl = binary.BigEndian.Uint32(v[3:7])
		payload = v[7:]
		// Reject if age exceeds total allowed lifetime (TTL + Lazy TTL)
		if uint64(elapsed) >= uint64(ttl)+uint64(c.args.LazyCacheTTL) {
			return nil, false, nil
		}
	} else {
		payload = v
	}

	// Decompression
	var data []byte
	var err error
	if c.args.CompressResp && len(payload) > 0 {
		if data, err = snappy.Decode(nil, payload); err != nil {
			return nil, false, err
		}
	} else {
		data = payload
	}

	msg := new(dns.Msg)
	if err = msg.Unpack(data); err != nil {
		return nil, false, err
	}

	// Legacy fallback for entries without binary headers
	if ttl == 0 {
		if len(msg.Answer) == 0 {
			ttl = uint32(defaultEmptyAnswerTTL / time.Second)
		} else {
			ttl = dnsutils.GetMinimalTTL(msg)
		}
		if uint64(elapsed) >= uint64(ttl)+uint64(c.args.LazyCacheTTL) {
			return nil, false, nil
		}
	}

	if elapsed < ttl {
		dnsutils.SubtractTTL(msg, elapsed)
		return msg, false, nil
	}
	if c.args.LazyCacheTTL <= 0 {
		return nil, false, nil
	}

	dnsutils.SetTTL(msg, uint32(c.args.LazyCacheReplyTTL))
	return msg, true, nil
}

func (c *cachePlugin) triggerLazyUpdate(key string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	go func() {
		_, _, _ = c.sf.Do(key, func() (any, error) {
			c.L().Debug("lazy update start", zap.String("key", key))
			lazyQCtx := qCtx.Copy()
			lazyQCtx.SetResponse(nil)
			
			ctx, cancel := context.WithTimeout(context.Background(), defaultLazyUpdateTimeout)
			if err := executable_seq.ExecChainNode(ctx, lazyQCtx, next); err != nil {
				c.L().Warn("lazy update failed", zap.Error(err), zap.String("key", key))
			} else if r := lazyQCtx.R(); r != nil {
				c.store(key, r)
				c.L().Debug("lazy update success", zap.String("key", key))
			}
			
			cancel() // Manual cleanup after execution
			return nil, nil
		})
	}()
}

func (c *cachePlugin) store(key string, r *dns.Msg) {
	if r.Truncated || (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) {
		return
	}

	var ttl uint32
	if len(r.Answer) == 0 {
		ttl = uint32(defaultEmptyAnswerTTL / time.Second)
	} else {
		ttl = dnsutils.GetMinimalTTL(r)
	}

	if ttl == 0 { return }

	raw, err := r.Pack()
	if err != nil {
		c.L().Debug("store pack error", zap.Error(err), zap.String("key", key))
		return
	}

	if c.args.CompressResp {
		raw = snappy.Encode(nil, raw)
	}

	// Store path: Header(7) + Payload
	bufWrapper := pool.GetBuf(7 + len(raw))
	data := bufWrapper.Bytes()
	binary.BigEndian.PutUint16(data[0:2], cacheMagic)
	data[2] = cacheVersion
	binary.BigEndian.PutUint32(data[3:7], ttl)
	copy(data[7:], raw)

	now := time.Now()
	storageTTL := time.Duration(ttl) * time.Second
	if c.args.LazyCacheTTL > 0 {
		storageTTL += time.Duration(c.args.LazyCacheTTL) * time.Second
	}

	c.backend.Store(key, data, now, now.Add(storageTTL))
	bufWrapper.Release() // Immediate manual release
}

func (c *cachePlugin) Shutdown() error {
	return c.backend.Close()
}
