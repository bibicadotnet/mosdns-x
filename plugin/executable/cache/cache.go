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

// Context helpers cho luồng cập nhật lazy ngầm.
type lazyBypassKey struct{}

func setLazyBypass(ctx context.Context) context.Context {
	return context.WithValue(ctx, lazyBypassKey{}, true)
}

func isLazyBypass(ctx context.Context) bool {
	v, _ := ctx.Value(lazyBypassKey{}).(bool)
	return v
}

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

	// Các trường được tính toán trước để tối ưu hiệu suất hot-path
	lazyEnabled  bool
	lazyWindow   time.Duration
	lazyReplyTTL uint32

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
	if args.LazyCacheTTL < 0 {
		return nil, fmt.Errorf("lazy_cache_ttl must >= 0")
	}
	if args.LazyCacheReplyTTL <= 0 {
		args.LazyCacheReplyTTL = 5
	}

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

	var whenHit executable_seq.Executable
	if tag := args.WhenHit; len(tag) > 0 {
		m := bp.M().GetExecutables()
		whenHit = m[tag]
		if whenHit == nil {
			return nil, fmt.Errorf("cannot find executable %s", tag)
		}
	}

	p_inst := &cachePlugin{
		BP:      bp,
		args:    args,
		backend: c,
		whenHit: whenHit,

		lazyEnabled:  args.LazyCacheTTL > 0,
		lazyWindow:   time.Duration(args.LazyCacheTTL) * time.Second,
		lazyReplyTTL: uint32(args.LazyCacheReplyTTL),

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
	bp.GetMetricsReg().MustRegister(p_inst.queryTotal, p_inst.hitTotal, p_inst.lazyHitTotal, p_inst.size)
	return p_inst, nil
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

	// 1. LOOKUP PATH: Bỏ qua lookup nếu đang trong luồng update ngầm (lazy bypass)
	if !isLazyBypass(ctx) {
		cachedResp, lazyHit, err := c.lookupCache(msgKey)
		if err != nil {
			c.L().Error("lookup cache", qCtx.InfoField(), zap.Error(err))
		}

		if cachedResp != nil {
			if lazyHit {
				c.lazyHitTotal.Inc()
				c.doLazyUpdate(msgKey, qCtx, next)
			}

			c.hitTotal.Inc()
			cachedResp.Id = q.Id

			// Log Warn để xác nhận HIT từ Phase 0
			c.L().Warn(
				"cache hit",
				qCtx.InfoField(),
				zap.String("cache_tag", c.Tag()),
				zap.String("hit_from", "phase0"),
				zap.Bool("lazy", lazyHit),
			)

			qCtx.SetResponse(cachedResp)
			// Quan trọng: Đánh dấu generation hiện tại đã được cache để tránh store đè ở phase sau
			qCtx.MarkAsCached()

			if c.whenHit != nil {
				return c.whenHit.Exec(ctx, qCtx, nil)
			}
			return nil
		}
	}

	// 2. MISS/BYPASS PATH: Thực thi các phase tiếp theo trong pipeline
	c.L().Debug("cache miss", qCtx.InfoField(), zap.String("tag", c.Tag()))
	err = executable_seq.ExecChainNode(ctx, qCtx, next)

	// 3. STORE PATH: 
	// Sử dụng logic Response Generation: Chỉ store nếu generation của response hiện tại chưa được cache.
	// Điều này cho phép Phase 5 store response mới ngay cả khi Phase 4 đã store response cũ.
	r := qCtx.R()
	if r != nil {
		if !qCtx.IsAlreadyCached() {
			if err := c.tryStoreMsg(msgKey, r); err != nil {
				c.L().Error("cache store", qCtx.InfoField(), zap.Error(err))
			} else {
				qCtx.MarkAsCached()
				c.L().Debug("stored", qCtx.InfoField(), zap.String("tag", c.Tag()), zap.Uint64("gen", qCtx.ResponseGen()))
			}
		} else {
			c.L().Debug("skipped", qCtx.InfoField(), zap.String("tag", c.Tag()), zap.Uint64("gen", qCtx.ResponseGen()))
		}
	}
	return err
}

func (c *cachePlugin) getMsgKey(q *dns.Msg) (string, error) {
	// Trạng thái chuẩn hóa của Key phụ thuộc vào các plugin đặt trước cache (như ecs_handler hoặc edns0_filter)
	return dnsutils.GetMsgKey(q, 0)
}

func (c *cachePlugin) lookupCache(msgKey string) (r *dns.Msg, lazyHit bool, err error) {
	v, storedTime, backendExpireAt := c.backend.Get(msgKey)
	if v == nil {
		return nil, false, nil
	}

	if c.args.CompressResp {
		decodeLen, err := snappy.DecodedLen(v)
		if err != nil {
			return nil, false, fmt.Errorf("snappy decode len err: %w", err)
		}
		if decodeLen > dns.MaxMsgSize {
			return nil, false, fmt.Errorf("invalid snappy data, data len: %d", decodeLen)
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

	now := time.Now()
	dnsExpireAt := backendExpireAt.Add(-c.lazyWindow)

	if now.Before(dnsExpireAt) {
		if elapsed := now.Unix() - storedTime.Unix(); elapsed > 0 {
			dnsutils.SubtractTTL(r, uint32(elapsed))
		}
		return r, false, nil
	}

	if c.lazyEnabled && now.Before(backendExpireAt) {
		dnsutils.SetTTL(r, c.lazyReplyTTL)
		return r, true, nil
	}

	return nil, false, nil
}

func (c *cachePlugin) doLazyUpdate(msgKey string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	lazyQCtx := qCtx.ShallowCopyForBackground()
	lazyUpdateFunc := func() (interface{}, error) {
		c.L().Debug("start lazy cache update", lazyQCtx.InfoField())
		defer c.lazyUpdateSF.Forget(msgKey)
		lazyCtx, cancel := context.WithTimeout(context.Background(), defaultLazyUpdateTimeout)
		defer cancel()

		lazyCtx = setLazyBypass(lazyCtx)

		err := executable_seq.ExecChainNode(lazyCtx, lazyQCtx, next)
		if err != nil {
			c.L().Warn("failed to update lazy cache", lazyQCtx.InfoField(), zap.Error(err))
		}

		// Self-healing trong luồng ngầm cũng sử dụng logic IsAlreadyCached
		r := lazyQCtx.R()
		if r != nil && !lazyQCtx.IsAlreadyCached() {
			if err := c.tryStoreMsg(msgKey, r); err != nil {
				c.L().Error("cache store", lazyQCtx.InfoField(), zap.Error(err))
			} else {
				lazyQCtx.MarkAsCached()
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

	v, err := r.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack response msg, %w", err)
	}

	now := time.Now()
	var msgTTL time.Duration
	if len(r.Answer) == 0 {
		msgTTL = defaultEmptyAnswerTTL
	} else {
		msgTTL = time.Duration(dnsutils.GetMinimalTTL(r)) * time.Second
	}

	if msgTTL == 0 && !c.lazyEnabled {
		return nil
	}

	expirationTime := now.Add(msgTTL + c.lazyWindow)

	if c.args.CompressResp {
		v = snappy.Encode(nil, v)
	}
	c.backend.Store(key, v, now, expirationTime)
	return nil
}

func (c *cachePlugin) Shutdown() error {
	return c.backend.Close()
}
