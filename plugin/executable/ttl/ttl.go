/*
 * Copyright (C) 2020-2026, IrineSistiana
 */

package ttl

import (
	"context"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "ttl"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

type Args struct {
	MaximumTTL uint32 `yaml:"maximum_ttl"`
	MinimalTTL uint32 `yaml:"minimal_ttl"`
}

type ttlPlugin struct {
	*coremain.BP
	max uint32
	min uint32
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	a := args.(*Args)
	return &ttlPlugin{
		BP:  bp,
		max: a.MaximumTTL,
		min: a.MinimalTTL,
	}, nil
}

func (t *ttlPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	r := qCtx.R()

	// Fast Path: If no response or no TTL constraints, move to next plugin immediately.
	if r == nil || (t.max == 0 && t.min == 0) {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// SINGLE-PASS OPTIMIZATION:
	// Instead of calling dnsutils helpers twice (which loops twice),
	// we iterate through all RR sections in a single pass.

	// Helper to process a slice of RRs
	processRRs := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if h := rr.Header(); h != nil {
				if t.max > 0 && h.Ttl > t.max {
					h.Ttl = t.max
				}
				if t.min > 0 && h.Ttl < t.min {
					h.Ttl = t.min
				}
			}
		}
	}

	processRRs(r.Answer)
	processRRs(r.Ns)
	processRRs(r.Extra)

	return executable_seq.ExecChainNode(ctx, qCtx, next)
}
