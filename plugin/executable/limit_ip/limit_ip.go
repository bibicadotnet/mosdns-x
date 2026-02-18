package limit_ip

import (
	"context"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "limit_ip"

func init() {
	// Standard plugin registration for custom limits in YAML
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} {
		return new(Args)
	})

	// Preset registration for quick access: _limit_2_ips
	coremain.RegNewPersetPluginFunc("_limit_2_ips", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &limitIPPlugin{BP: bp, limit: 2}, nil
	})
}

// CRITICAL: Explicitly assert that limitIPPlugin implements ExecutablePlugin.
// Without this, Mosdns may register the plugin but never trigger the Exec function.
var _ coremain.ExecutablePlugin = (*limitIPPlugin)(nil)

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
// YAML CONFIGURATION WARNING:
// In Mosdns, the response processing order is the REVERSE of the YAML order.
//
// To ensure logic correctness, place this ABOVE '_no_cname' in your YAML:
// - _limit_2_ips  (TOP: Processes response LAST)
// - _no_cname     (BOTTOM: Processes response FIRST)
func (p *limitIPPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	// 1. Forward execution to next nodes and wait for Upstream response
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	// 2. Early Exit:
	// Handle nil responses or answers already within the limit (~1ns hot path).
	if r == nil || len(r.Answer) <= p.limit {
		return nil
	}

	// 3. In-place Truncation:
	// Safe to truncate now because _no_cname (below in YAML) has already
	// flattened the response during the initial phase of the response stack.
	r.Answer = r.Answer[:p.limit]

	return nil
}
