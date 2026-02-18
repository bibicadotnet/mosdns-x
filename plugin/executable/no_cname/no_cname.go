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

// Exec strips CNAME records and flattens responses.
//
// PIPELINE POSITION:
// This plugin MUST be placed at the BOTTOM of your 'exec' sequence
// (immediately before '- _return') to process responses first.
//
// Example YAML:
//    - ... (other plugins)
//    - _no_cname    <-- Place at the BOTTOM
//    - _return
func (t *noCNAME) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	// 1. Upstream execution first (wait for response).
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	// Early exit: If response is nil or Answer is empty, no modification is needed.
	if r == nil || len(r.Answer) == 0 {
		return nil
	}

	ans := r.Answer
	qName := r.Question[0].Name
	writeIdx := 0

	// 2. UNIVERSAL IN-PLACE FLATTENING:
	// Instead of explicit QType checks (A/AAAA), we use writeIdx as a content-based filter.
	// - For IP queries: writeIdx increments, flattening occurs.
	// - For non-IP queries (SRV, MX, TXT): writeIdx remains 0, returning original response.
	// This single-pass approach is zero-allocation and handles all edge cases safely.
	for i := 0; i < len(ans); i++ {
		rr := ans[i]
		rt := rr.Header().Rrtype

		if rt == dns.TypeA || rt == dns.TypeAAAA {
			// Pointer swap: rewrite name to match original question.
			rr.Header().Name = qName
			ans[writeIdx] = rr
			writeIdx++
		}
	}

	// 3. SAFE EXIT:
	// If no IP records were found, return the original response as-is.
	// This ensures we don't break non-IP queries or IP queries with no glue records.
	if writeIdx == 0 {
		return nil
	}

	// 4. FINAL CLEANUP:
	// Truncate Answer in-place. Wipe Authority (Ns) and Extra (EDNS0) sections.
	// At this stage, only pure IP records are required for the client.
	r.Answer = ans[:writeIdx]
	r.Ns = nil
	r.Extra = nil

	return nil
}
