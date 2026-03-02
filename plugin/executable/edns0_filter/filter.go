package edns0_filter

import (
	"context"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "edns0_filter"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
	coremain.RegNewPersetPluginFunc("_edns0_filter_no_edns0", func(bp *coremain.BP) (coremain.Plugin, error) {
		return NewFilter(bp, &Args{NoEDNS: true}), nil
	})
	coremain.RegNewPersetPluginFunc("_edns0_filter_ecs_only", func(bp *coremain.BP) (coremain.Plugin, error) {
		return NewFilter(bp, &Args{Keep: []uint16{dns.EDNS0SUBNET}}), nil
	})
}

type Args struct {
	// Args priority: NoEDNS > Keep > Discard.
	NoEDNS  bool     `yaml:"no_edns"`
	Keep    []uint16 `yaml:"accept"`
	Discard []uint16 `yaml:"discard"`
}

var _ coremain.ExecutablePlugin = (*Filter)(nil)

type Filter struct {
	*coremain.BP
	args    *Args
	keep    map[uint16]struct{}
	discard map[uint16]struct{}
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return NewFilter(bp, args.(*Args)), nil
}

func NewFilter(bp *coremain.BP, args *Args) *Filter {
	newMapOrNil := func(opts []uint16) map[uint16]struct{} {
		if len(opts) == 0 {
			return nil
		}
		// Pre-allocation to avoid dynamic rehashing during boot
		m := make(map[uint16]struct{}, len(opts))
		for _, option := range opts {
			m[option] = struct{}{}
		}
		return m
	}

	return &Filter{
		BP:      bp,
		args:    args,
		keep:    newMapOrNil(args.Keep),
		discard: newMapOrNil(args.Discard),
	}
}

func (s *Filter) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	s.applyFilter(q) // FAIL-FAST: Trust the architecture. If q is nil, panic here.
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (s *Filter) applyFilter(q *dns.Msg) {
	switch {
	case s.args.NoEDNS:
		dnsutils.RemoveEDNS0(q)

	case len(s.keep) > 0:
		opt := q.IsEdns0()
		if opt == nil || len(opt.Option) == 0 {
			break
		}
		// OPTIMAL: Reuse backing array without closure overhead
		opts := opt.Option[:0]
		for _, o := range opt.Option {
			if _, accept := s.keep[o.Option()]; accept {
				opts = append(opts, o)
			}
		}
		opt.Option = opts

	case len(s.discard) > 0:
		opt := q.IsEdns0()
		if opt == nil || len(opt.Option) == 0 {
			break
		}
		opts := opt.Option[:0]
		for _, o := range opt.Option {
			if _, remove := s.discard[o.Option()]; !remove {
				opts = append(opts, o)
			}
		}
		opt.Option = opts

	default: // remove all edns0 options
		if opt := q.IsEdns0(); opt != nil {
			opt.Option = nil // ZERO-ALLOCATION
		}
	}
}
