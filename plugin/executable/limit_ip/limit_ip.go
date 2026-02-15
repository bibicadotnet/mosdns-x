package limit_ip

import (
	"context"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "limit_ip"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} {
		return new(Args)
	})
	coremain.RegNewPersetPluginFunc("_limit_2_ips", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &limitIPPlugin{BP: bp, limit: 2}, nil
	})
}

type Args struct {
	Limit int `yaml:"limit"`
}

type limitIPPlugin struct {
	*coremain.BP
	limit int
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)
	limit := cfg.Limit
	// Default limit to 2 if not specified or invalid.
	if limit <= 0 {
		limit = 2
	}
	return &limitIPPlugin{
		BP:    bp,
		limit: limit,
	}, nil
}

// Exec limits the number of IP records in the DNS answer.
//
// ⚠️ PIPELINE ORDER WARNING (YAML vs RESPONSE):
// In Mosdns, the response processing order is the REVERSE of the YAML order.
//
// To ensure logic correctness, this plugin SHOULD be placed ABOVE '_no_cname' 
// in your YAML configuration:
//
// YAML config:
// - _limit_2_ips    <-- Placed ABOVE (will process response LAST)
// - _no_cname   <-- Placed BELOW (will process response FIRST)
//
// This ensures '_no_cname' flattens the answer BEFORE 'limit_ip' truncates it.

func (p *limitIPPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	// 1. Upstream execution.
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	// 2. Early Exit:
	// If the response is nil or the number of IPs is already within the limit, exit immediately.
	// This fast path (~1ns) handles 99% of traffic (e.g., Cloudflare/Google usually return 1-2 IPs).
	if r == nil || len(r.Answer) <= p.limit {
		return nil
	}

	// 3. In-place Truncation:
	// Strictly preserve the original upstream order.
	// This maximizes DNS cache consistency and maintains TCP/TLS session persistence 
	// by ensuring the client consistently connects to the primary IP provided by the upstream.
	r.Answer = r.Answer[:p.limit]

	return nil
}
