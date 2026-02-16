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
		mg, err := domain.BatchLoadDomainProvider(args.CNAME, bp.M().GetDataManager())
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

// equalDNSName performs an ASCII case-insensitive comparison.
// This is faster than strings.EqualFold as it avoids Unicode overhead.
func equalDNSName(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca == cb {
			continue
		}
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func (e *hasValidAnswer) match(qCtx *query_context.Context) bool {
	r := qCtx.R()
	if r == nil {
		return false
	}

	// Trusted Invariant: qCtx.Q().Question[0] is guaranteed by entry_handler.
	target := qCtx.Q().Question[0]

	for _, rr := range r.Answer {
		h := rr.Header()
		// Only Type and Name are checked. Class is enforced as INET at Server Layer.
		if h.Rrtype == target.Qtype && equalDNSName(h.Name, target.Name) {
			return true
		}
	}
	return false
}

func (e *hasValidAnswer) Match(_ context.Context, qCtx *query_context.Context) (matched bool, err error) {
	return e.match(qCtx), nil
}
