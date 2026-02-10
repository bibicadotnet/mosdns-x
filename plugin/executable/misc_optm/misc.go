package misc_optm

import (
	"context"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const (
	PluginType = "misc_optm"
)

func init() {
	coremain.RegNewPersetPluginFunc("_misc_optm", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &optm{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*optm)(nil)

type optm struct {
	*coremain.BP
}

func (t *optm) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()

	// 1. GATEKEEPER: Strict header and structure validation.
	// Filter out malformed or unusual queries early to protect downstream plugins.
	// After this, downstream plugins can safely assume q.Question[0] is valid.
	if isUnusualQuery(q) {
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeRefused)
		qCtx.SetResponse(r)
		return nil
	}

	// Request-side EDNS logic is removed as it's redundant with the user's phase-based design.
	// Handover to downstream plugins (Cache, Forwarder, ECS, etc.)
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

// isUnusualQuery performs strict DNS hygiene checks according to RFC 1035.
func isUnusualQuery(q *dns.Msg) bool {
	// Header Flags Check:
	// - Response: Must be 0 (Query).
	// - Opcode: Must be 0 (Standard Query).
	// - AA, TC, RA: Must be 0 in a query. If set, the query is malformed.
	// - Zero: Reserved Z bits must be 0.
	if q.Response || q.Opcode != dns.OpcodeQuery ||
		q.Authoritative || q.Truncated || q.RecursionAvailable || q.Zero {
		return true
	}

	// Body Structure Check:
	// - Exactly one question is required for standard processing.
	// - Qclass must be INET.
	// - Answer and Authority sections must be empty for a clean query.
	if len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET ||
		len(q.Answer) != 0 || len(q.Ns) != 0 {
		return true
	}

	return false
}
