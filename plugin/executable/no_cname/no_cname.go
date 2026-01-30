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

	// 1. Only target A/AAAA queries
	qType := r.Question[0].Qtype
	if qType != dns.TypeA && qType != dns.TypeAAAA {
		return nil
	}

	// 2. Quick check for IP records to maintain original semantics and optimize allocs
	hasIP := false
	for _, rr := range r.Answer {
		if t := rr.Header().Rrtype; t == dns.TypeA || t == dns.TypeAAAA {
			hasIP = true
			break
		}
	}
	if !hasIP {
		return nil
	}
	
	qName := r.Question[0].Name
	var filtered []dns.RR
	
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeCNAME {
			continue
		}
		
		// 3. Deep Copy to prevent memory racing and side-effects on cached records
		newRR := dns.Copy(rr)
		newRR.Header().Name = qName
		filtered = append(filtered, newRR)
	}
	
	r.Answer = filtered
	r.Extra = nil 
	
	return nil
}
