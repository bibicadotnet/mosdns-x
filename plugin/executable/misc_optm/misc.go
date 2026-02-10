package misc_optm

import (
	"context"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const (
	PluginType = "misc_optm"
	maxUDPSize = 1232
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
	// Trust the architecture: qCtx.Q() is guaranteed by the entry point.
	// If q is nil, panic here is better than a delayed crash elsewhere.

	// 1. Filter out unusual queries early to minimize processing.
	if isUnusualQuery(q) {
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeRefused)
		qCtx.SetResponse(r)
		return nil
	}

	// 2. Request side: Fix EDNS0 UDP size to prevent fragmentation.
	// Combined checks into a single 'if' for slightly cleaner flow.
	if opt := q.IsEdns0(); opt != nil && opt.UDPSize() > maxUDPSize {
		opt.SetUDPSize(maxUDPSize)
	}

	// EXECUTION BOUNDARY: Handover to downstream plugins (Cache, Forwarder, etc.)
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	// 3. Response side: Cleanup and Consistency
	r := qCtx.R()
	if r == nil {
		return nil
	}

	// Always remove Padding from response to minimize packet size.
	if rOpt := r.IsEdns0(); rOpt != nil {
		dnsutils.RemoveEDNS0Option(rOpt, dns.EDNS0PADDING)
	}

	// Ensure EDNS0 consistency: Response must not have EDNS0 if the request doesn't.
	// q.IsEdns0() must be re-checked here as downstream plugins might have mutated it.
	if q.IsEdns0() == nil {
		dnsutils.RemoveEDNS0(r)
	}

	return nil
}

// isUnusualQuery is inlined manually to reduce function call overhead in the hot path.
func isUnusualQuery(q *dns.Msg) bool {
	// Standard Query Header Checks
	if q.Response || q.Opcode != dns.OpcodeQuery || q.Authoritative || q.Zero {
		return true
	}
	// Body Structure Checks: Must have 1 Question (INET) and no Answer/Authority sections.
	if len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET ||
		len(q.Answer) != 0 || len(q.Ns) != 0 {
		return true
	}
	return false
}
