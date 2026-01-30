package retry_servfail

import (
	"context"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const (
	PluginType = "retry_servfail"
)

func init() {
	coremain.RegNewPersetPluginFunc("_retry_servfail", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &retryServfail{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*retryServfail)(nil)

type retryServfail struct {
	*coremain.BP
}

// isPermanentEDE returns true if the EDE code indicates a permanent failure
// where retrying would be useless.
func isPermanentEDE(code uint16) bool {
	switch code {
	case
		9,  // DNSSEC Bogus
		15, // Blocked
		16, // Censored
		17, // Filtered
		22, // No Reachable Authoritative (Lame delegation)
		23: // Network Error (Authoritative server unresponsive)
		return true
	default:
		return false
	}
}

func (t *retryServfail) Exec(
	ctx context.Context,
	qCtx *query_context.Context,
	next executable_seq.ExecutableChainNode,
) error {
	// 1st attempt: Execute the remaining chain (typically upstream)
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	shouldRetry := false

	if r == nil {
		// Transport error or nil response
		shouldRetry = true
	} else if r.Rcode == dns.RcodeServerFailure && len(r.Ns) == 0 {
		// Default to retry for empty SERVFAIL
		shouldRetry = true

		// Check for Extended DNS Errors (EDE) in Extra records
		for _, extra := range r.Extra {
			if opt, ok := extra.(*dns.OPT); ok {
				for _, option := range opt.Option {
					if ede, ok := option.(*dns.EDNS0_EDE); ok {
						if isPermanentEDE(ede.InfoCode) {
							// Domain is confirmed dead or blocked, do not retry
							shouldRetry = false
							break
						}
					}
				}
			}
			if !shouldRetry {
				break
			}
		}
	}

	if shouldRetry {
		t.L().Debug("transient failure detected, retrying upstream", qCtx.InfoField())
		// Clear failed response state from context before retry
		qCtx.SetResponse(nil)
		// 2nd attempt: Re-execute the remaining chain
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	return nil
}
