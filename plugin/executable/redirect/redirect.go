/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
	if len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	orgQName := q.Question[0].Name
	redirectTarget, ok := r.m.Match(orgQName)
	if !ok {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}

	// Change query name to the redirect target
	q.Question[0].Name = redirectTarget
	err := executable_seq.ExecChainNode(ctx, qCtx, next)

	if resp := qCtx.R(); resp != nil {
		// 1. Restore the original query name in the Question section
		for i := range resp.Question {
			if resp.Question[i].Name == redirectTarget {
				resp.Question[i].Name = orgQName
			}
		}

		// 2. Filter out CNAMEs and rewrite Answer record names to the original name
		filteredAns := make([]dns.RR, 0, len(resp.Answer))
		for _, rr := range resp.Answer {
			// Skip CNAME records to avoid protocol conflicts and keep the result clean
			if rr.Header().Rrtype == dns.TypeCNAME {
				continue
			}
			// Rewrite the record name (A/AAAA) to match the original query
			if rr.Header().Name == redirectTarget {
				rr.Header().Name = orgQName
			}
			filteredAns = append(filteredAns, rr)
		}
		resp.Answer = filteredAns
	}

	return err
}

func (r *redirectPlugin) Close() error {
	_ = r.m.Close()
	return nil
}
