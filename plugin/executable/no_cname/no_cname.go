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

// Exec strips CNAME records from DNS responses and flattens all Answer records 
// to match the original query name. This ensures the client receives a 
// direct mapping (e.g., Question A -> Answer A) without exposing the CNAME chain.
func (t *noCNAME) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	// 1. Execute upstream chain first to get the response
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}
	
	r := qCtx.R()
	if r == nil || len(r.Question) == 0 || len(r.Answer) == 0 {
		return nil
	}

	// 2. Only process A (IPv4) and AAAA (IPv6) queries
	qType := r.Question[0].Qtype
	if qType != dns.TypeA && qType != dns.TypeAAAA {
		return nil
	}

	// 3. Safety Check: Only trigger flattening if the response contains at least one IP record (A/AAAA).
	// This prevents unintended modifications to SRV, TXT, or empty responses.
	hasIP := false
	for _, rr := range r.Answer {
		if rt := rr.Header().Rrtype; rt == dns.TypeA || rt == dns.TypeAAAA {
			hasIP = true
			break
		}
	}
	if !hasIP {
		return nil
	}
	
	qName := r.Question[0].Name
	// Pre-allocate slice with capacity to minimize memory re-allocations
	filtered := make([]dns.RR, 0, len(r.Answer))
	
	// 4. Rewrite all Answer records after removing CNAMEs to match the original Question name
	for _, rr := range r.Answer {
		// Strictly skip CNAME records
		if rr.Header().Rrtype == dns.TypeCNAME {
			continue
		}
		
		// CRITICAL: Deep copy each record before rewriting the Name.
		// This is essential for thread-safety and to prevent polluting the shared cache.
		newRR := dns.Copy(rr)
		newRR.Header().Name = qName
		filtered = append(filtered, newRR)
	}
	
	// 5. Final Sanitization: Replace Answer section and purge Extra data
	r.Answer = filtered
	r.Extra = nil 
	
	return nil
}
