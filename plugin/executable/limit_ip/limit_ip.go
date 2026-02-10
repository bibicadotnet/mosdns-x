/*
 * Copyright (C) 2020-2026, IrineSistiana
 */

package limit_ip

import (
	"context"
	"math/rand/v2" // Go 1.22+ Fast, Zero-lock, per-P random source.

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "limit_ip"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} {
		return new(Args)
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
	if limit <= 0 {
		limit = 3
	}
	return &limitIPPlugin{
		BP:    bp,
		limit: limit,
	}, nil
}

func (p *limitIPPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	// 1. Upstream execution
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	// 2. Minimal Branching: Exit fast if no work is needed.
	if r == nil || len(r.Answer) <= 1 {
		return nil
	}

	// --- ULTRA FAST PATH (ZERO-ALLOC, LOCK-FREE) ---
	//
	// CRITICAL INVARIANT:
	// - r.Answer MUST contain ONLY homogeneous IP RRset (all A or all AAAA).
	// - Non-IP records (CNAME, etc.) or mixed RRsets MUST be filtered by upstream.
	// - This assumption is required for zero-branch correctness and peak performance.
	//
	// Violating this invariant WILL lead to incorrect response semantics (e.g. truncated CNAMEs).
	
	ans := r.Answer
	n := len(ans)

	// 3. In-place Shuffle: 
	// Uses math/rand/v2 global source which is optimized for concurrency.
	// Cost: ~5-10ns.
	rand.Shuffle(n, func(i, j int) {
		ans[i], ans[j] = ans[j], ans[i]
	})

	// 4. In-place Truncation:
	// Direct slice manipulation, zero memory movement.
	// Cost: ~1ns.
	if n > p.limit {
		r.Answer = ans[:p.limit]
	}

	return nil
}
