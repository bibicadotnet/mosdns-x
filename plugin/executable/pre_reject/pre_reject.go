/*
 * _pre_reject is a heuristic pre-filter to reduce DNS noise and 
 * common human typing errors. It is NOT a security or blacklist engine.
 *
 * Usage in config:
 * - _pre_reject
 */

package pre_reject

import (
	"context"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const PluginType = "_pre_reject"

func init() {
	coremain.RegNewPersetPluginFunc(PluginType, func(bp *coremain.BP) (coremain.Plugin, error) {
		return &preReject{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*preReject)(nil)

type preReject struct {
	*coremain.BP
}

func (p *preReject) Exec(
	ctx context.Context,
	qCtx *query_context.Context,
	next executable_seq.ExecutableChainNode,
) error {

	q := qCtx.Q()
	q0 := q.Question[0]
	qt := q0.Qtype

	// Block QTYPE
	if qt == dns.TypeAAAA ||
		qt == dns.TypePTR ||
		qt == dns.TypeHTTPS {

		qCtx.SetResponse(dnsutils.GenEmptyReply(q, dns.RcodeSuccess))
		return nil
	}

	name := q0.Name

	hasDot := false

	// ignore trailing dot
	for i := 0; i < len(name)-1; i++ {
		c := name[i]

		if !validChar[c] {
			return reject(q, qCtx)
		}

		if c == '.' {
			hasDot = true
		}
	}

	// Missing dot / TLD
	if !hasDot {
		return reject(q, qCtx)
	}

	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func reject(q *dns.Msg, qCtx *query_context.Context) error {
	qCtx.SetResponse(dnsutils.GenEmptyReply(q, dns.RcodeNameError))
	return nil
}

var validChar = [256]bool{
	'.': true, '-': true, '_': true,

	'0': true, '1': true, '2': true, '3': true, '4': true,
	'5': true, '6': true, '7': true, '8': true, '9': true,

	'a': true, 'b': true, 'c': true, 'd': true, 'e': true,
	'f': true, 'g': true, 'h': true, 'i': true, 'j': true,
	'k': true, 'l': true, 'm': true, 'n': true, 'o': true,
	'p': true, 'q': true, 'r': true, 's': true, 't': true,
	'u': true, 'v': true, 'w': true, 'x': true, 'y': true,
	'z': true,

	'A': true, 'B': true, 'C': true, 'D': true, 'E': true,
	'F': true, 'G': true, 'H': true, 'I': true, 'J': true,
	'K': true, 'L': true, 'M': true, 'N': true, 'O': true,
	'P': true, 'Q': true, 'R': true, 'S': true, 'T': true,
	'U': true, 'V': true, 'W': true, 'X': true, 'Y': true,
	'Z': true,
}
