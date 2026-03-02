package redirect

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "redirect"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*redirectPlugin)(nil)

type Args struct {
	Rule []string `yaml:"rule"`
}

type redirectPlugin struct {
	*coremain.BP
	m *domain.MatcherGroup[string]
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newRedirect(bp, args.(*Args))
}

func newRedirect(bp *coremain.BP, args *Args) (*redirectPlugin, error) {
	parseFunc := func(s string) (p, v string, err error) {
		f := strings.Fields(s)
		if len(f) != 2 {
			return "", "", fmt.Errorf("redirect rule must have 2 fields, but got %d", len(f))
		}
		return f[0], dns.Fqdn(f[1]), nil
	}
	staticMatcher := domain.NewMixMatcher[string]()
	staticMatcher.SetDefaultMatcher(domain.MatcherFull)
	m, err := domain.BatchLoadProvider[string](
		args.Rule,
		staticMatcher,
		parseFunc,
		bp.M().GetDataManager(),
		func(b []byte) (domain.Matcher[string], error) {
			mixMatcher := domain.NewMixMatcher[string]()
			mixMatcher.SetDefaultMatcher(domain.MatcherFull)
			if err := domain.LoadFromTextReader[string](mixMatcher, bytes.NewReader(b), parseFunc); err != nil {
				return nil, err
			}
			return mixMatcher, nil
		},
	)
	if err != nil {
		return nil, err
	}
	bp.L().Info("redirect rules loaded", zap.Int("length", m.Len()))
	return &redirectPlugin{
		BP: bp,
		m:  m,
	}, nil
}

func (r *redirectPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	// Guard: Minimal safety for INET queries
	if q == nil || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	orgQName := q.Question[0].Name
	redirectTarget, ok := r.m.Match(orgQName)
	if !ok {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// PHASE 1: Forward Path - Rewrite Request
	q.Question[0].Name = redirectTarget
	err := executable_seq.ExecChainNode(ctx, qCtx, next)

	// PHASE 2: Reverse Path - Restore Protocol Integrity
	resp := qCtx.R()
	if resp == nil {
		return err
	}

	// Deterministic Restore: Force orgQName on Question section.
	// Faster than string comparison and resilient against upstream normalization.
	if len(resp.Question) > 0 {
		resp.Question[0].Name = orgQName
	}

	// Early exit if no answers exist (e.g., NXDOMAIN, SERVFAIL, NODATA)
	if len(resp.Answer) == 0 {
		return err
	}

	// PHASE 3: High-Performance Filtering (In-place & Zero-allocation)
	// Uses index-based loop for better CPU cache utilization and branch prediction.
	ans := resp.Answer
	n := 0
	for i := 0; i < len(ans); i++ {
		rr := ans[i]
		h := rr.Header() // Header is never nil for valid DNS RRs decoded by mosdns

		// Stealth: Strip CNAME records to hide internal redirection logic
		if h.Rrtype == dns.TypeCNAME {
			continue
		}

		// Flattening: Rewrite record name back to the original query name (Pointer swap)
		if h.Name == redirectTarget {
			h.Name = orgQName
		}

		ans[n] = rr
		n++
	}
	// Truncate the slice to the filtered length
	resp.Answer = ans[:n]

	return err
}

func (r *redirectPlugin) Close() error {
	_ = r.m.Close()
	return nil
}
