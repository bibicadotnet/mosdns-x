package reverselookup

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/cache"
	"github.com/pmkol/mosdns-x/pkg/cache/mem_cache"
	"github.com/pmkol/mosdns-x/pkg/cache/redis_cache"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

const (
	PluginType = "reverse_lookup"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*reverseLookup)(nil)

type Args struct {
	Size      int    `yaml:"size"` // Default is 64*1024
	Redis     string `yaml:"redis"`
	HandlePTR bool   `yaml:"handle_ptr"`
	TTL       int    `yaml:"ttl"` // Default is 1800 (30min)
}

func (a *Args) initDefault() *Args {
	if a.Size <= 0 {
		a.Size = 64 * 1024
	}
	if a.TTL <= 0 {
		a.TTL = 1800
	}
	return a
}

type reverseLookup struct {
	*coremain.BP
	args *Args
	c    cache.Backend
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newReverseLookup(bp, args.(*Args))
}

func newReverseLookup(bp *coremain.BP, args *Args) (coremain.Plugin, error) {
	args.initDefault()
	var c cache.Backend
	if u := args.Redis; len(u) > 0 {
		opts, err := redis.ParseURL(u)
		if err != nil {
			return nil, fmt.Errorf("invalid redis url, %w", err)
		}
		r := redis.NewClient(opts)
		rc, err := redis_cache.NewRedisCache(redis_cache.RedisCacheOpts{
			Client:       r,
			ClientCloser: r,
			Logger:       bp.L(),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to init redis cache, %w", err)
		}
		c = rc
	} else {
		c = mem_cache.NewMemCache(args.Size, 0)
	}
	p := &reverseLookup{
		BP:   bp,
		args: args,
		c:    c,
	}
	return p, nil
}

func (p *reverseLookup) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	if r := p.handlePTRQuery(q); r != nil {
		qCtx.SetResponse(r)
		return nil
	}

	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}
	p.saveIPs(q, qCtx.R())
	return nil
}

func (p *reverseLookup) Close() error {
	return p.c.Close()
}

func (p *reverseLookup) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ipStr := req.URL.Query().Get("ip")
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	d := p.lookup(netip.AddrFrom16(addr.As16()))
	w.Write([]byte(d))
}

func (p *reverseLookup) lookup(n netip.Addr) string {
	v, _, _, ok := p.c.Get(as16(n).String())
	if !ok {
		return ""
	}
	return string(v)
}

func (p *reverseLookup) handlePTRQuery(q *dns.Msg) *dns.Msg {
	if p.args.HandlePTR && len(q.Question) > 0 && q.Question[0].Qtype == dns.TypePTR {
		question := q.Question[0]
		addr, _ := utils.ParsePTRName(question.Name)
		if !addr.IsValid() {
			return nil
		}
		fqdn := p.lookup(addr)
		if len(fqdn) > 0 {
			r := new(dns.Msg)
			r.SetReply(q)
			r.Answer = append(r.Answer, &dns.PTR{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: question.Qtype,
					Class:  question.Qclass,
					Ttl:    5,
				},
				Ptr: fqdn,
			})
			return r
		}
	}
	return nil
}

func (p *reverseLookup) saveIPs(q, r *dns.Msg) {
	if r == nil {
		return
	}

	nowNano := time.Now().UnixNano()

	for _, rr := range r.Answer {
		var ip net.IP
		switch rr := rr.(type) {
		case *dns.A:
			ip = rr.A
		case *dns.AAAA:
			ip = rr.AAAA
		default:
			continue
		}

		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		
		h := rr.Header()
		// --- GIỮ LẠI LOGIC GIỚI HẠN TTL ---
		currentTTL := int(h.Ttl)
		if currentTTL > p.args.TTL {
			currentTTL = p.args.TTL
		}
		// ---------------------------------

		name := h.Name
		if len(q.Question) == 1 {
			name = q.Question[0].Name
		}

		// Tính toán mốc hết hạn theo Nano
		expire := nowNano + (int64(currentTTL) * 1e9)
		p.c.Store(as16(addr).String(), []byte(name), expire, expire)
	}
}

func as16(n netip.Addr) netip.Addr {
	if n.Is6() {
		return n
	}
	return netip.AddrFrom16(n.As16())
}
