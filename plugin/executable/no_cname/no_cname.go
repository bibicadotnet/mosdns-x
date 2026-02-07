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
//
// CRITICAL: Rebuilds the message from scratch to ensure proper DNS name compression,
// reducing message size from ~80 bytes to ~60 bytes (vs upstream with EDNS at 71 bytes).
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

	// 3. Check if response contains IP records and CNAME records
	hasIP := false
	hasCNAME := false
	for _, rr := range r.Answer {
		rt := rr.Header().Rrtype
		if rt == dns.TypeA || rt == dns.TypeAAAA {
			hasIP = true
		} else if rt == dns.TypeCNAME {
			hasCNAME = true
		}
		// Early exit optimization
		if hasIP && hasCNAME {
			break
		}
	}

	// 4. Safety check: Only process if there are actual IP records
	if !hasIP {
		return nil
	}

	// 5. Always strip Extra section (OPT/EDNS) to reduce message size
	r.Extra = nil

	// 6. If no CNAME exists, keep original response (already optimal)
	if !hasCNAME {
		return nil
	}

	// 7. REBUILD MESSAGE from scratch to enable proper DNS name compression
	// This is CRITICAL because:
	// - Setting r.Compress = true on an already-parsed message does NOT work
	// - dns.Copy() creates independent string literals that bypass compression
	// - Only a fresh message with Compress=true will use pointer compression (C0 0C)
	
	qName := r.Question[0].Name
	newMsg := new(dns.Msg)
	newMsg.SetReply(r) // Copies header flags (QR, Opcode, RD, RA, etc.)
	newMsg.Compress = true // MUST be set BEFORE adding records

	// 8. Filter CNAME records and rebuild Answer section with optimized record creation
	for _, rr := range r.Answer {
		// Skip CNAME records entirely
		if rr.Header().Rrtype == dns.TypeCNAME {
			continue
		}

		// Create new RR header with question name for compression
		hdr := dns.RR_Header{
			Name:   qName, // All answers point to original question name
			Rrtype: rr.Header().Rrtype,
			Class:  rr.Header().Class,
			Ttl:    rr.Header().Ttl,
		}

		// Type-specific record creation (avoids heavy dns.Copy() overhead)
		switch v := rr.(type) {
		case *dns.A:
			// IPv4 address record - most common case
			newMsg.Answer = append(newMsg.Answer, &dns.A{
				Hdr: hdr,
				A:   v.A, // Copy IP address (4 bytes)
			})
		case *dns.AAAA:
			// IPv6 address record
			newMsg.Answer = append(newMsg.Answer, &dns.AAAA{
				Hdr:  hdr,
				AAAA: v.AAAA, // Copy IP address (16 bytes)
			})
		default:
			// Fallback for other record types (SRV, MX, TXT, etc.)
			// This shouldn't happen for A/AAAA queries, but handle it gracefully
			newRR := dns.Copy(rr)
			newRR.Header().Name = qName
			newMsg.Answer = append(newMsg.Answer, newRR)
		}
	}

	// 9. Replace response with compressed message
	// When mosdns calls Pack() on this message:
	// - Question: bibica.net. (full name, 11 bytes)
	// - Answer 1: C0 0C (pointer to offset 12, 2 bytes) + A record data
	// - Answer 2: C0 0C (pointer to offset 12, 2 bytes) + A record data
	// Result: ~60 bytes vs ~80 bytes without compression
	qCtx.SetResponse(newMsg)

	return nil
}
