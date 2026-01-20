/*
 * Copyright (C) 2020-2025, pmkol
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

package no_cname

import (
	"context"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const (
	PluginType = "no_cname"
)

func init() {
	coremain.RegNewPersetPluginFunc("_" + PluginType, func(bp *coremain.BP) (coremain.Plugin, error) {
		return &noCNAME{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*noCNAME)(nil)

type noCNAME struct {
	*coremain.BP
}

func (t *noCNAME) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	if q == nil || len(q.Question) == 0 {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}
	originalName := q.Question[0].Name

	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	if r == nil || len(r.Answer) == 0 {
		return nil
	}

	hasIP := false
	for _, rr := range r.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeDNAME:
			return nil
		case dns.TypeA, dns.TypeAAAA:
			hasIP = true
		}
	}

	if !hasIP {
		return nil
	}

	filtered := make([]dns.RR, 0, len(r.Answer))
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeCNAME {
			continue
		}
		
		newRR := dns.Copy(rr)
		newRR.Header().Name = originalName
		filtered = append(filtered, newRR)
	}

	r.Answer = filtered
	return nil
}
