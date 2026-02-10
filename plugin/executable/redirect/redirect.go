/*
 * Copyright (C) 2020-2026, IrineSistiana
 */

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
	// Basic defensive guard for malformed queries
	if q == nil || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	orgQName := q.Question[0].Name
	redirectTarget, ok := r.m.Match(orgQName)
	if !ok {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// Change query name to the redirect target for upstream processing
	q.Question[0].Name = redirectTarget
	err := executable_seq.ExecChainNode(ctx, qCtx, next)

	if resp := qCtx.R(); resp != nil {
		// 1. Restore the original query name in the Question section
		// Since we guarded len == 1 above, we only need to check the first question
		if len(resp.Question) > 0 && resp.Question[0].Name == redirectTarget {
			resp.Question[0].Name = orgQName
		}

		// 2. In-place filtering and rewriting (Zero-allocation optimization)
		// We reuse the existing Answer slice to avoid heap allocation.
		n := 0
		for _, rr := range resp.Answer {
			h := rr.Header()
			if h == nil {
				continue
			}

			// Skip CNAME records to hide the redirection logic from the client
			if h.Rrtype == dns.TypeCNAME {
				continue
			}

			// Rewrite the record name back to the original query name
			if h.Name == redirectTarget {
				h.Name = orgQName
			}

			// Keep this record by moving it to the front of the slice
			resp.Answer[n] = rr
			n++
		}
		// Truncate the slice to the new filtered length
		resp.Answer = resp.Answer[:n]
	}

	return err
}

func (r *redirectPlugin) Close() error {
	_ = r.m.Close()
	return nil
}
