package limit_ip

import (
	"context"
	"math/rand/v2"
	"strings"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "limit_ip"

// Pre-defined suffixes to avoid heap allocation in hot-path.
var githubSuffixes = []string{
	"github.com.",
	"github.io.",
	"githubusercontent.com.",
	"githubassets.com.",
	"githubcopilot.com.",
	"github-cloud.s3.amazonaws.com.",
}

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} {
		return new(Args)
	})
}

type Args struct {
	Limit int `yaml:"limit"`
}

type limitIPPlugin struct {
	*coremain.BP
	limit int
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	cfg := args.(*Args)
	limit := cfg.Limit
	if limit <= 0 {
		limit = 2
	}
	return &limitIPPlugin{
		BP:    bp,
		limit: limit,
	}, nil
}

func (p *limitIPPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	// 1. Upstream execution first.
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	// 2. DEFENSIVE GUARD: Exit if no response or empty answer.
	r := qCtx.R()
	if r == nil || len(r.Answer) == 0 {
		return nil
	}

	// 3. QUESTION GUARD: Avoid panic on malformed queries or reordered pipelines.
	q := qCtx.Q()
	if q == nil || len(q.Question) == 0 {
		return nil
	}

	ans := r.Answer
	n := len(ans)
	qName := strings.ToLower(q.Question[0].Name)

	// 4. FQDN NORMALIZATION: Ensure trailing dot for reliable suffix matching.
	if !strings.HasSuffix(qName, ".") {
		qName += "."
	}

	// 5. TARGETED SHUFFLE: Strictly for GitHub ecosystem.
	// We only shuffle if n > 1 to avoid wasted cycles.
	// For Cloudflare (n=2) or others, we keep upstream order to PROTECT DNS CACHE.
	if n > 1 {
		isGitHub := false
		for _, suffix := range githubSuffixes {
			if strings.HasSuffix(qName, suffix) {
				isGitHub = true
				break
			}
		}

		if isGitHub {
			rand.Shuffle(n, func(i, j int) {
				ans[i], ans[j] = ans[j], ans[i]
			})
		}
	}

	// 6. IN-PLACE TRUNCATION: Always apply limit.
	// Preserves original upstream order if not GitHub.
	if n > p.limit {
		r.Answer = ans[:p.limit]
	}

	return nil
}
