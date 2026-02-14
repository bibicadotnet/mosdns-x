package cache

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
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

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
	coremain.RegNewPersetPluginFunc("_default_cache", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newCachePlugin(bp, &Args{})
	})
}

type Args struct {
	Size              int    `yaml:"size"`
	Redis             string `yaml:"redis"`
	RedisTimeout      int    `yaml:"redis_timeout"`
	LazyCacheTTL      int    `yaml:"lazy_cache_ttl"`
	LazyCacheReplyTTL int    `yaml:"lazy_cache_reply_ttl"`
	CleanerInterval   *int   `yaml:"cleaner_interval"`
}

type cachePlugin struct {
	*coremain.BP
	args *Args

	backend      cache.Backend
	lazyUpdateSF singleflight.Group

	// Runtime optimized constants
	lazyEnabled  bool
	lazyWindow   time.Duration
	lazyReplyTTL uint32

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
	var err error

	if len(args.Redis) != 0 {
		opt, err := redis.ParseURL(args.Redis)
		if err != nil {
			return nil, fmt.Errorf("invalid redis url: %w", err)
		}
		opt.MaxRetries = -1
		r := redis.NewClient(opt)
		rcOpts := redis_cache.RedisCacheOpts{
			Client:        r,
			ClientCloser:  r,
			ClientTimeout: time.Duration(args.RedisTimeout) * time.Millisecond,
			Logger:        bp.L(),
		}
		// Tránh shadow biến c bằng cách dùng err2
		var err2 error
		c, err2 = redis_cache.NewRedisCache(rcOpts)
		if err2 != nil {
			return nil, fmt.Errorf("redis cache init: %w", err2)
		}
	} else {
		cleanerSec := 60
		if args.CleanerInterval != nil {
			cleanerSec = *args.CleanerInterval
		}
		// Enforce cleaner >= lazy để đảm bảo dữ liệu stale không bị xóa trước khi kịp update
		if args.LazyCacheTTL > cleanerSec {
			cleanerSec = args.LazyCacheTTL + 10
		}
		c = mem_cache.NewMemCache(args.Size, time.Duration(cleanerSec)*time.Second)
	}

	p := &cachePlugin{
		BP:           bp,
		args:         args,
		backend:      c,
		lazyEnabled:  args.LazyCacheTTL > 0,
		lazyWindow:   time.Duration(args.LazyCacheTTL) * time.Second,
		lazyReplyTTL: uint32(args.LazyCacheReplyTTL),
	}
	if p.lazyReplyTTL == 0 {
		p.lazyReplyTTL = 5
	}

	p.queryTotal = prometheus.NewCounter(prometheus.CounterOpts{Name: "query_total", Help: "Total processed queries"})
	p.hitTotal = prometheus.NewCounter(prometheus.CounterOpts{Name: "hit_total", Help: "Total cache hits"})
	p.lazyHitTotal = prometheus.NewCounter(prometheus.CounterOpts{Name: "lazy_hit_total", Help: "Total stale hits in lazy window"})
	p.size = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "cache_size", Help: "Current cache records count"}, func() float64 {
		return float64(c.Len())
	})

	bp.GetMetricsReg().MustRegister(p.queryTotal, p.hitTotal, p.lazyHitTotal, p.size)
	return p, nil
}

func (c *cachePlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	c.queryTotal.Inc()
	q := qCtx.Q()
	msgKey, _ := dnsutils.GetMsgKey(q, 0)
	if len(msgKey) == 0 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// 1. LOOKUP (Hot-path start)
	raw, _, expireAt := c.backend.Get(msgKey)
	if raw == nil {
		goto miss
	}

	now := time.Now()

	// 2. LINEAR PATH LOGIC (Optimized for Branch Predictor)
	if !c.lazyEnabled {
		remaining := expireAt.Sub(now)
		if remaining <= 0 {
			goto miss
		}
		// Trả về Normal Hit
		if err := c.fastHit(qCtx, q.Id, raw, uint32(remaining.Seconds())+1); err != nil {
			c.L().Warn("corrupt cache entry", zap.String("key", msgKey), zap.Error(err))
			goto miss
		}
		return nil
	}

	// LAZY LOGIC: [Fresh Zone] -> [Stale Zone] -> [Miss Zone]
	lazyBoundary := expireAt.Add(-c.lazyWindow)

	if now.Before(lazyBoundary) {
		// Fresh Hit (Trường hợp phổ biến nhất)
		remaining := lazyBoundary.Sub(now)
		if remaining <= 0 {
			goto miss
		}
		if err := c.fastHit(qCtx, q.Id, raw, uint32(remaining.Seconds())+1); err != nil {
			c.L().Warn("corrupt cache entry", zap.String("key", msgKey), zap.Error(err))
			goto miss
		}
		return nil
	}

	if now.Before(expireAt) {
		// Stale Hit (Lazy Window)
		c.lazyHitTotal.Inc()
		c.doLazyUpdate(msgKey, qCtx, next)
		if err := c.fastHit(qCtx, q.Id, raw, c.lazyReplyTTL); err != nil {
			c.L().Warn("corrupt stale cache entry", zap.String("key", msgKey), zap.Error(err))
			goto miss
		}
		return nil
	}

miss:
	err := executable_seq.ExecChainNode(ctx, qCtx, next)
	if err == nil {
		if r := qCtx.R(); r != nil {
			_ = c.tryStoreRaw(msgKey, r)
		}
	}
	return err
}

func (c *cachePlugin) fastHit(qCtx *query_context.Context, id uint16, raw []byte, ttl uint32) error {
	// Thuê buffer từ pool
	buf := pool.GetBuf(len(raw))
	out := buf.Bytes()[:len(raw)]
	copy(out, raw)

	// In-place binary patching (Zero Unpack)
	if err := streamingPatchTTL(out, ttl); err != nil {
		buf.Release()
		return err
	}

	// Patch Transaction ID (2 bytes đầu)
	binary.BigEndian.PutUint16(out[0:2], id)

	// Gán buffer thô vào context. Network layer chịu trách nhiệm Release().
	qCtx.SetRawResponse(buf)
	c.hitTotal.Inc() // Chỉ tăng metric khi thực sự gán thành công
	return nil
}

func (c *cachePlugin) tryStoreRaw(key string, r *dns.Msg) error {
	if (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) || r.Truncated {
		return nil
	}
	raw, err := r.Pack()
	if err != nil {
		return err
	}

	ttl := uint32(300)
	if len(r.Answer) > 0 {
		ttl = dnsutils.GetMinimalTTL(r)
	}
	if ttl == 0 {
		return nil
	}

	now := time.Now()
	// TTL DNS thật sự
	expireAtDNS := now.Add(time.Duration(ttl) * time.Second)

	// Tính toán mốc xóa của Backend (DNS TTL + Lazy window)
	backendExpireAt := expireAtDNS
	if c.lazyEnabled {
		backendExpireAt = expireAtDNS.Add(c.lazyWindow)
	}

	c.backend.Store(key, raw, now, backendExpireAt)
	return nil
}

func (c *cachePlugin) doLazyUpdate(msgKey string, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) {
	lazyQCtx := qCtx.ShallowCopyForBackground()

	// Sử dụng Singleflight để chống cache stampede cho cùng 1 key
	go func() {
		_, _, _ = c.lazyUpdateSF.Do(msgKey, func() (interface{}, error) {
			defer c.lazyUpdateSF.Forget(msgKey)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			if err := executable_seq.ExecChainNode(ctx, lazyQCtx, next); err == nil {
				if r := lazyQCtx.R(); r != nil {
					_ = c.tryStoreRaw(msgKey, r)
				}
			}
			return nil, nil
		})
	}()
}

// --- Wire Format Logic (High-Speed Streaming) ---



func streamingPatchTTL(buf []byte, ttl uint32) error {
	if len(buf) < 12 {
		return errors.New("short packet")
	}
	qd := int(binary.BigEndian.Uint16(buf[4:6]))
	an := int(binary.BigEndian.Uint16(buf[6:8]))
	ns := int(binary.BigEndian.Uint16(buf[8:10]))
	ar := int(binary.BigEndian.Uint16(buf[10:12]))

	off := 12
	// 1. Skip Question Section
	for i := 0; i < qd; i++ {
		off = skipName(buf, off)
		if off < 0 {
			return errors.New("malformed question name")
		}
		off += 4 // type(2) + class(2)
		if off > len(buf) {
			return errors.New("question overflow")
		}
	}

	// 2. Patch Answer, Authority, Additional Sections
	total := an + ns + ar
	for i := 0; i < total; i++ {
		off = skipName(buf, off)
		if off < 0 {
			return errors.New("malformed rr name")
		}
		if off+8 > len(buf) {
			return errors.New("rr header overflow")
		}

		off += 4 // skip type & class
		binary.BigEndian.PutUint32(buf[off:off+4], ttl)
		off += 4

		if off+2 > len(buf) {
			return errors.New("missing rdlen")
		}
		rdlen := int(binary.BigEndian.Uint16(buf[off:off+2]))
		off += 2 + rdlen

		if off > len(buf) {
			return errors.New("rdata overflow")
		}
	}
	return nil
}

func skipName(buf []byte, off int) int {
	for off < len(buf) {
		l := buf[off]
		off++
		if l == 0 {
			return off
		}
		if l >= 0xC0 { // DNS Pointer
			if off >= len(buf) {
				return -1
			}
			return off + 1
		}
		off += int(l)
		if off > len(buf) {
			return -1
		}
	}
	return -1
}

func (c *cachePlugin) Shutdown() error {
	return c.backend.Close()
}
