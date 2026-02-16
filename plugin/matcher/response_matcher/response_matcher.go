/*
 * Copyright (C) 2020-2026, IrineSistiana
 */

package responsematcher

import (
	"context"
	"io"

	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
	"github.com/pmkol/mosdns-x/pkg/matcher/elem"
	"github.com/pmkol/mosdns-x/pkg/matcher/msg_matcher"
	"github.com/pmkol/mosdns-x/pkg/matcher/netlist"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "response_matcher"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
	coremain.RegNewPersetPluginFunc("_response_valid_answer", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &hasValidAnswer{BP: bp}, nil
	})
}

var _ coremain.MatcherPlugin = (*responseMatcher)(nil)

type Args struct {
	RCode []int    `yaml:"rcode"`
	IP    []string `yaml:"ip"`
	CNAME []string `yaml:"cname"`
}

type responseMatcher struct {
	*coremain.BP
	args *Args

	matcherGroup []executable_seq.Matcher
	closer       []io.Closer
}

func (m *responseMatcher) Match(ctx context.Context, qCtx *query_context.Context) (matched bool, err error) {
	return executable_seq.LogicalAndMatcherGroup(ctx, qCtx, m.matcherGroup)
}

func (m *responseMatcher) Close() error {
	for _, closer := range m.closer {
		_ = closer.Close()
	}
	return nil
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newResponseMatcher(bp, args.(*Args))
}

func newResponseMatcher(bp *coremain.BP, args *Args) (m *responseMatcher, err error) {
	m = new(responseMatcher)
	m.BP = bp
	m.args = args

	if len(args.RCode) > 0 {
		m.matcherGroup = append(m.matcherGroup, msg_matcher.NewRCodeMatcher(elem.NewIntMatcher(args.RCode)))
	}

	if len(args.CNAME) > 0 {
		mg, err := domain.BatchLoadDomainProvider(
			args.CNAME,
			bp.M().GetDataManager(),
		)
		if err != nil {
			return nil, err
		}
		m.matcherGroup = append(m.matcherGroup, msg_matcher.NewCNameMatcher(mg))
		m.closer = append(m.closer, mg)
		bp.L().Info("cname matcher loaded", zap.Int("length", mg.Len()))
	}

	if len(args.IP) > 0 {
		l, err := netlist.BatchLoadProvider(args.IP, bp.M().GetDataManager())
		if err != nil {
			return nil, err
		}
		m.matcherGroup = append(m.matcherGroup, msg_matcher.NewAAAAAIPMatcher(l))
		m.closer = append(m.closer, l)
		bp.L().Info("ip matcher loaded", zap.Int("length", l.Len()))
	}

	return m, nil
}

type hasValidAnswer struct {
	*coremain.BP
}

var _ coremain.MatcherPlugin = (*hasValidAnswer)(nil)

func (e *hasValidAnswer) match(qCtx *query_context.Context) bool {
	r := qCtx.R()
	q := qCtx.Q()

	// Minimal guards to ensure the plugin is self-contained and crash-proof.
	// Negligible CPU cost compared to the performance gain from loop simplification.
	if r == nil || q == nil || len(q.Question) == 0 {
		return false
	}

	// Optimization: Direct access to the primary question.
	// Bypasses nested loops based on standard DNS query behavior.
	question := q.Question[0]

	// Efficient linear scan of the Answer section.
	for _, rr := range r.Answer {
		h := rr.Header()
		// Validating record against the original question.
		if h.Rrtype == question.Qtype &&
			h.Class == question.Qclass &&
			h.Name == question.Name {
			return true
		}
	}

	return false
}

func (e *hasValidAnswer) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	return e.match(qCtx), nil
}
