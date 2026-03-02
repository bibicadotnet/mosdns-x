/*
 * Copyright (C) 2020-2026, IrineSistiana
 */

package blackhole

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "blackhole"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })

	// Preset plugins for common RCode responses
	coremain.RegNewPersetPluginFunc("_drop_response", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newBlackHole(bp, &Args{RCode: -1})
	})
	coremain.RegNewPersetPluginFunc("_new_empty_response", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newBlackHole(bp, &Args{RCode: dns.RcodeSuccess})
	})
	coremain.RegNewPersetPluginFunc("_new_servfail_response", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newBlackHole(bp, &Args{RCode: dns.RcodeServerFailure})
	})
	coremain.RegNewPersetPluginFunc("_new_nxdomain_response", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newBlackHole(bp, &Args{RCode: dns.RcodeNameError})
	})
	coremain.RegNewPersetPluginFunc("_new_refused_response", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newBlackHole(bp, &Args{RCode: dns.RcodeRefused})
	})
	coremain.RegNewPersetPluginFunc("_new_formerr_response", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newBlackHole(bp, &Args{RCode: dns.RcodeFormatError})
	})
	coremain.RegNewPersetPluginFunc("_new_notimp_response", func(bp *coremain.BP) (coremain.Plugin, error) {
		return newBlackHole(bp, &Args{RCode: dns.RcodeNotImplemented})
	})
}

var _ coremain.ExecutablePlugin = (*blackHole)(nil)

type blackHole struct {
	*coremain.BP
	args *Args

	// Pre-parsed IP addresses
	ipv4 []netip.Addr
	ipv6 []netip.Addr
}

type Args struct {
	IPv4  []string `yaml:"ipv4"`
	IPv6  []string `yaml:"ipv6"`
	RCode int      `yaml:"rcode"`
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newBlackHole(bp, args.(*Args))
}

func newBlackHole(bp *coremain.BP, args *Args) (*blackHole, error) {
	b := &blackHole{BP: bp, args: args}
	for _, s := range args.IPv4 {
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("invalid ipv4 addr: %s", s)
		}
		b.ipv4 = append(b.ipv4, addr)
	}
	for _, s := range args.IPv6 {
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is6() {
			return nil, fmt.Errorf("invalid ipv6 addr: %s", s)
		}
		b.ipv6 = append(b.ipv6, addr)
	}
	return b, nil
}

func (b *blackHole) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	b.exec(qCtx)
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

// exec logic invariant:
// 1. qCtx.Q() is validated by _misc_optm (non-nil, len(Question) == 1).
func (b *blackHole) exec(qCtx *query_context.Context) {
	q := qCtx.Q()
	question := q.Question[0]

	// Optimization: Handle the most common case (RCode only) first to reduce branching.
	if len(b.ipv4) == 0 && len(b.ipv6) == 0 {
		if b.args.RCode >= 0 {
			qCtx.SetResponse(dnsutils.GenEmptyReply(q, b.args.RCode))
		} else {
			qCtx.SetResponse(nil) // Drop
		}
		return
	}

	qName := question.Name
	qType := question.Qtype

	switch {
	case qType == dns.TypeA && len(b.ipv4) > 0:
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeSuccess)
		r.RecursionAvailable = true
		r.Answer = make([]dns.RR, 0, len(b.ipv4))
		for _, addr := range b.ipv4 {
			r.Answer = append(r.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				A: addr.AsSlice(),
			})
		}
		qCtx.SetResponse(r)

	case qType == dns.TypeAAAA && len(b.ipv6) > 0:
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeSuccess)
		r.RecursionAvailable = true
		r.Answer = make([]dns.RR, 0, len(b.ipv6))
		for _, addr := range b.ipv6 {
			r.Answer = append(r.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				AAAA: addr.AsSlice(),
			})
		}
		qCtx.SetResponse(r)

	case b.args.RCode >= 0:
		qCtx.SetResponse(dnsutils.GenEmptyReply(q, b.args.RCode))

	default:
		qCtx.SetResponse(nil)
	}
}
