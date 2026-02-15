/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 */

package no_cname

import (
	"context"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "no_cname"

func init() {
	coremain.RegNewPersetPluginFunc("_no_cname", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &noCNAME{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*noCNAME)(nil)

type noCNAME struct {
	*coremain.BP
}

// Exec strips CNAME records and flattens responses for A/AAAA queries.
// Optimized for maximum performance: zero-allocation, in-place mutation.
func (t *noCNAME) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	// Early exit: if response is nil or Answer is empty, no flattening required.
	if r == nil || len(r.Answer) == 0 {
		return nil
	}

	// Hot-path optimization: Only process A/AAAA queries.
	// Other types like HTTPS (65) or SRV (33) are returned as-is to prevent semantic breakage.
	q := r.Question[0]
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return nil
	}

	ans := r.Answer
	qName := q.Name
	writeIdx := 0
	hasIP := false

	// --- SINGLE PASS IN-PLACE FLATTENING ---
	// Iterate once to filter and rewrite names simultaneously.
	// Avoids dns.Copy() by mutating the RR Header Name pointer directly (Zero-allocation).
	for i := 0; i < len(ans); i++ {
		rr := ans[i]
		rt := rr.Header().Rrtype

		if rt == dns.TypeA || rt == dns.TypeAAAA {
			hasIP = true
			
			// In-place name rewrite. Pointer assignment is extremely cheap.
			rr.Header().Name = qName
			
			ans[writeIdx] = rr
			writeIdx++
		}
	}

	// If no IP records found (e.g., CNAME pointing to non-IP types),
	// return original response to maintain client-side logic.
	if !hasIP {
		return nil
	}

	// Truncate Answer slice in-place to avoid new slice allocation.
	r.Answer = ans[:writeIdx]

	// --- ULTRA FAST EXTRA CLEANUP ---
	// Since this plugin resides at the end of the pipeline, OPT (EDNS0) is no longer needed.
	// Assigning nil is a 0ns operation to wipe the Extra section.
	r.Extra = nil

	return nil
}
