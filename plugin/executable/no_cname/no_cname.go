package no_cname

import (
	"context"
	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "no_cname"

func init() {
	coremain.RegNewPersetPluginFunc("_no_cname", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &noCNAME{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*noCNAME)(nil)

type noCNAME struct {
	*coremain.BP
}

func (t *noCNAME) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	if r == nil || len(r.Question) == 0 || len(r.Answer) == 0 {
		return nil
	}

	qType := r.Question[0].Qtype
	if qType != dns.TypeA && qType != dns.TypeAAAA {
		return nil
	}

	hasIP := false
	hasCNAME := false
	for _, rr := range r.Answer {
		rt := rr.Header().Rrtype
		if rt == dns.TypeA || rt == dns.TypeAAAA {
			hasIP = true
		} else if rt == dns.TypeCNAME {
			hasCNAME = true
		}
		if hasIP && hasCNAME {
			break
		}
	}

	if !hasIP {
		return nil
	}

	r.Extra = nil

	if !hasCNAME {
		return nil
	}

	qName := r.Question[0].Name
	filtered := make([]dns.RR, 0, len(r.Answer))

	for _, rr := range r.Answer {
		rt := rr.Header().Rrtype
		
		if rt != dns.TypeA && rt != dns.TypeAAAA {
			continue
		}

		newRR := dns.Copy(rr)
		newRR.Header().Name = qName
		filtered = append(filtered, newRR)
	}

	r.Answer = filtered
	r.Compress = true

	packed, err := r.Pack()
	if err != nil {
		return nil
	}

	compressed := new(dns.Msg)
	if err := compressed.Unpack(packed); err != nil {
		return nil
	}

	qCtx.SetResponse(compressed)
	return nil
}
