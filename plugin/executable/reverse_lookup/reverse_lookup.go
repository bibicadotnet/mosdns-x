package reverselookup

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/cache/mem_cache"
	// "github.com/pmkol/mosdns-x/pkg/cache/redis_cache" // Nếu redis_cache chưa upgrade interface thì tạm thời dùng mem_cache
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
	Size      int    `yaml:"size"`
	Redis     string `yaml:"redis"`
	HandlePTR bool   `yaml:"handle_ptr"`
	TTL       int    `yaml:"ttl"`
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
	// Dùng trực tiếp mem_cache để tránh lỗi interface nếu redis_cache chưa upgrade
	c    *mem_cache.MemCache 
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newReverseLookup(bp, args.(*Args))
}

func newReverseLookup(bp *coremain.BP, args *Args) (coremain.Plugin, error) {
	args.initDefault()
	
	// Lưu ý: Tôi đổi sang dùng mem_cache trực tiếp vì Backend interface cũ đã bị phá bỏ
	// Nếu ông muốn dùng Redis, ông phải upgrade redis_cache.go theo interface mới.
	c := mem_cache.NewMemCache(args.Size, 0)
	
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

	d := p.lookup(addr)
	w.Write([]byte(d))
}

func (p *reverseLookup) lookup(n netip.Addr) string {
	// Khớp với interface Get: trả về 6 giá trị
	// offsets và count không dùng cho reverse lookup nên bỏ qua (_)
	v, _, _, _, _, ok := p.c.Get(as16(n).String())
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

	now := time.Now().Unix() // Đồng nhất sang GIÂY

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
		currentTTL := int(h.Ttl)
		if currentTTL > p.args.TTL {
			currentTTL = p.args.TTL
		}

		name := h.Name
		if len(q.Question) == 1 {
			name = q.Question[0].Name
		}

		// Tính toán mốc hết hạn theo GIÂY
		expire := now + int64(currentTTL)
		
		// Truyền 8 đối số cho Store: 
		// offsets = [8]uint16{}, count = 0 (vì đây không phải DNS message thô)
		p.c.Store(as16(addr).String(), []byte(name), expire, expire, [8]uint16{}, 0)
	}
}

func as16(n netip.Addr) netip.Addr {
	if n.Is6() {
		return n
	}
	return netip.AddrFrom16(n.As16())
}
