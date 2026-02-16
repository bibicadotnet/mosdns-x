/*
 * _pre_reject is a heuristic pre-filter to reduce DNS noise and 
 * common human typing errors. It is NOT a security or blacklist engine.
 *
 * Usage in config:
 * - _pre_reject
 */

package pre_reject

import (
	"context"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "_pre_reject"

func init() {
	coremain.RegNewPersetPluginFunc(PluginType, func(bp *coremain.BP) (coremain.Plugin, error) {
		return &preReject{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*preReject)(nil)

type preReject struct {
	*coremain.BP
}

func (p *preReject) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	// Skip if packet is empty to avoid panics
	if q == nil || len(q.Question) == 0 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	qt := q.Question[0].Qtype

	// ====================================================================
	// PHASE 1: QTYPE FILTERING (Noise reduction & protocol hygiene)
	// ====================================================================
	switch qt {
	case dns.TypeAAAA, dns.TypePTR, dns.TypeHTTPS: // Drop IPv6, PTR, and HTTPS records early
		// Return empty NOERROR (NODATA) with SOA for negative caching
		qCtx.SetResponse(dnsutils.GenEmptyReply(q, dns.RcodeSuccess))
		return nil
	}

	// ====================================================================
	// PHASE 2: DOMAIN VALIDATION (Common human typing errors)
	// ====================================================================
	name := q.Question[0].Name
	hasInternalDot := false

	// Fast byte scan for invalid characters (faster than regex)
	for i := 0; i < len(name)-1; i++ { // name ends with a trailing dot
		c := name[i]
		if c == '.' {
			hasInternalDot = true
			continue
		}
		// Allow: alphanumeric, dash, underscore
		// Reject: !, @, #, $, %, ^, &, *, spaces, etc.
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return p.rejectNX(q, qCtx)
		}
	}

	// Reject if domain lacks a TLD (e.g. "google" instead of "google.com")
	if !hasInternalDot {
		return p.rejectNX(q, qCtx)
	}

	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (p *preReject) rejectNX(q *dns.Msg, qCtx *query_context.Context) error {
	// Return NXDOMAIN with SOA for negative caching
	qCtx.SetResponse(dnsutils.GenEmptyReply(q, dns.RcodeNameError))
	return nil
}
