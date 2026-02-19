/*
 * Copyright (C) 2020-2026, IrineSistiana
 *
 * This file is part of mosdns.
 */

package querymatcher

import (
	"context"
	"io"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
	"github.com/pmkol/mosdns-x/pkg/matcher/elem"
	"github.com/pmkol/mosdns-x/pkg/matcher/msg_matcher"
	"github.com/pmkol/mosdns-x/pkg/matcher/netlist"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "query_matcher"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })

	// Optimized presets using specialized structs for maximum performance
	coremain.RegNewPersetPluginFunc(
		"_qtype_A_AAAA",
		func(bp *coremain.BP) (coremain.Plugin, error) {
			return &qTypeA_AAAA{BP: bp}, nil
		},
	)
	coremain.RegNewPersetPluginFunc(
		"_qtype_AAAA",
		func(bp *coremain.BP) (coremain.Plugin, error) {
			return &qTypeAAAA{BP: bp}, nil
		},
	)

	coremain.RegNewPersetPluginFunc(
		"_query_edns0",
		func(bp *coremain.BP) (coremain.Plugin, error) {
			return &queryIsEDNS0{BP: bp}, nil
		},
	)
}

var _ coremain.MatcherPlugin = (*queryMatcher)(nil)

type Args struct {
	ClientIP []string `yaml:"client_ip"`
	ECS      []string `yaml:"ecs"`
	Domain   []string `yaml:"domain"`
	QType    []int    `yaml:"qtype"`
	QClass   []int    `yaml:"qclass"`
}

type queryMatcher struct {
	*coremain.BP
	args *Args

	matcherGroup []executable_seq.Matcher
	closer       []io.Closer
}

func (m *queryMatcher) Match(ctx context.Context, qCtx *query_context.Context) (matched bool, err error) {
	return executable_seq.LogicalAndMatcherGroup(ctx, qCtx, m.matcherGroup)
}

func (m *queryMatcher) Close() error {
	for _, closer := range m.closer {
		_ = closer.Close()
	}
	return nil
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newQueryMatcher(bp, args.(*Args))
}

func newQueryMatcher(bp *coremain.BP, args *Args) (m *queryMatcher, err error) {
	m = new(queryMatcher)
	m.BP = bp
	m.args = args

	if len(args.ClientIP) > 0 {
		l, err := netlist.BatchLoadProvider(args.ClientIP, bp.M().GetDataManager())
		if err != nil {
			return nil, err
		}
		m.matcherGroup = append(m.matcherGroup, msg_matcher.NewClientIPMatcher(l))
		m.closer = append(m.closer, l)
		bp.L().Info("client ip matcher loaded", zap.Int("length", l.Len()))
	}
	if len(args.ECS) > 0 {
		l, err := netlist.BatchLoadProvider(args.ECS, bp.M().GetDataManager())
		if err != nil {
			return nil, err
		}
		m.matcherGroup = append(m.matcherGroup, msg_matcher.NewClientECSMatcher(l))
		m.closer = append(m.closer, l)
		bp.L().Info("ecs ip matcher loaded", zap.Int("length", l.Len()))
	}
	if len(args.Domain) > 0 {
		mg, err := domain.BatchLoadDomainProvider(
			args.Domain,
			bp.M().GetDataManager(),
		)
		if err != nil {
			return nil, err
		}
		m.matcherGroup = append(m.matcherGroup, msg_matcher.NewQNameMatcher(mg))
		m.closer = append(m.closer, mg)
		bp.L().Info("domain matcher loaded", zap.Int("length", mg.Len()))
	}
	if len(args.QType) > 0 {
		m.matcherGroup = append(m.matcherGroup, msg_matcher.NewQTypeMatcher(elem.NewIntMatcher(args.QType)))
	}
	if len(args.QClass) > 0 {
		m.matcherGroup = append(m.matcherGroup, msg_matcher.NewQClassMatcher(elem.NewIntMatcher(args.QClass)))
	}

	return m, nil
}

// ----------------------------------------------------------------------------
// Performance Optimized Preset Matchers
// Logic Invariant: Only executed after entry_handler gatekeeper validation.
// ----------------------------------------------------------------------------

type qTypeA_AAAA struct{ *coremain.BP }

func (m *qTypeA_AAAA) Match(_ context.Context, qCtx *query_context.Context) (bool, error) {
	t := qCtx.Q().Question[0].Qtype
	return t == dns.TypeA || t == dns.TypeAAAA, nil
}

type qTypeAAAA struct{ *coremain.BP }

func (m *qTypeAAAA) Match(_ context.Context, qCtx *query_context.Context) (bool, error) {
	return qCtx.Q().Question[0].Qtype == dns.TypeAAAA, nil
}

type queryIsEDNS0 struct{ *coremain.BP }

func (q *queryIsEDNS0) Match(_ context.Context, qCtx *query_context.Context) (bool, error) {
	return qCtx.Q().IsEdns0() != nil, nil
}
