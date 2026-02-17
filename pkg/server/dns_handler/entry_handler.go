/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 */

package dns_handler

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

const (
	defaultQueryTimeout = time.Second * 5
)

var nopLogger = zap.NewNop()

type Handler interface {
	ServeDNS(ctx context.Context, req *dns.Msg, meta *query_context.RequestMeta) (*dns.Msg, error)
}

type EntryHandlerOpts struct {
	Logger             *zap.Logger
	Entry              executable_seq.Executable
	QueryTimeout       time.Duration
	RecursionAvailable bool
}

func (opts *EntryHandlerOpts) Init() error {
	if opts.Logger == nil {
		opts.Logger = nopLogger
	}
	if opts.Entry == nil {
		return errors.New("nil entry")
	}
	utils.SetDefaultNum(&opts.QueryTimeout, defaultQueryTimeout)
	return nil
}

type EntryHandler struct {
	opts EntryHandlerOpts
}

func NewEntryHandler(opts EntryHandlerOpts) (Handler, error) {
	if err := opts.Init(); err != nil {
		return nil, err
	}
	return &EntryHandler{opts: opts}, nil
}

func (h *EntryHandler) ServeDNS(ctx context.Context, req *dns.Msg, meta *query_context.RequestMeta) (*dns.Msg, error) {
	// 1. Context & Deadline Setup
	qCtx := ctx
	cancel := func() {}

	ddl := time.Now().Add(h.opts.QueryTimeout)
	if d, ok := ctx.Deadline(); !ok || d.After(ddl) {
		qCtx, cancel = context.WithDeadline(ctx, ddl)
	}
	defer cancel()

	// 2. Optimized Structural & Protocol Validation
	if len(req.Question) != 1 {
		h.opts.Logger.Debug("refused: invalid question count", zap.Uint16("id", req.Id))
		return h.responseRefused(req), nil
	}

	if req.Opcode != dns.OpcodeQuery {
		h.opts.Logger.Debug("refused: unusual opcode", zap.Uint16("id", req.Id))
		return h.responseRefused(req), nil
	}

	// 3. RFC 8482 & Early Noise Filtering
	q := req.Question[0]

	// Block ANY Queries Early (RFC 8482)
	if q.Qtype == dns.TypeANY {
		h.opts.Logger.Debug("blocked: ANY query (RFC 8482)", zap.Uint16("id", req.Id))
		r := new(dns.Msg)
		r.SetReply(req)
		r.Answer = []dns.RR{&dns.HINFO{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeHINFO,
				Class:  dns.ClassINET,
				Ttl:    8482,
			},
			Cpu: "ANY obsoleted",
			Os:  "See RFC 8482",
		}}
		if h.opts.RecursionAvailable {
			r.RecursionAvailable = true
		}
		return r, nil
	}

	// Block noisy qtypes (AAAA, PTR, HTTPS) - high volume, reject before context allocation
	if q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypePTR || q.Qtype == dns.TypeHTTPS {
		r := new(dns.Msg)
		r.SetRcode(req, dns.RcodeSuccess)
		if h.opts.RecursionAvailable {
			r.RecursionAvailable = true
		}
		return r, nil
	}

	// 4. Domain Validation (Reject typos and missing TLD)
	name := q.Name
	hasDot := false
	for i := 0; i < len(name)-1; i++ {
		c := name[i]
		if !preRejectValidChar[c] {
			return h.responseNXDomain(req), nil
		}
		if c == '.' {
			hasDot = true
		}
	}
	if !hasDot {
		return h.responseNXDomain(req), nil
	}

	// Normalize domain to lowercase once at boundary.
	req.Question[0].Name = strings.ToLower(name)

	// 5. Final Hygiene Checks
	if q.Qclass != dns.ClassINET {
		h.opts.Logger.Debug("refused: unsupported qclass", zap.Uint16("id", req.Id))
		return h.responseRefused(req), nil
	}

	if req.Response || req.Authoritative || req.Truncated ||
		req.RecursionAvailable || req.Zero || len(req.Answer) != 0 || len(req.Ns) != 0 {
		h.opts.Logger.Debug("refused: malformed header flags or sections", zap.Uint16("id", req.Id))
		return h.responseRefused(req), nil
	}

	// 6. Execution Flow
	origID := req.Id
	queryCtx := query_context.NewContext(req, meta)

	err := h.opts.Entry.Exec(qCtx, queryCtx, nil)
	respMsg := queryCtx.R()

	// 7. Logging
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			h.opts.Logger.Debug("query interrupted", queryCtx.InfoField(), zap.Error(err))
		} else {
			h.opts.Logger.Warn("entry returned an err", queryCtx.InfoField(), zap.Error(err))
		}
	}

	// 8. Response Finalization
	if respMsg == nil {
		if err == nil {
			h.opts.Logger.Error("entry returned with nil response", queryCtx.InfoField())
		}

		respMsg = new(dns.Msg)
		respMsg.SetReply(req)

		if err != nil {
			respMsg.Rcode = dns.RcodeServerFailure
		} else {
			respMsg.Rcode = dns.RcodeRefused
		}
	}

	if h.opts.RecursionAvailable {
		respMsg.RecursionAvailable = true
	}
	respMsg.Id = origID

	return respMsg, nil
}

func (h *EntryHandler) responseRefused(req *dns.Msg) *dns.Msg {
	res := new(dns.Msg)
	res.SetReply(req)
	res.Rcode = dns.RcodeRefused
	if h.opts.RecursionAvailable {
		res.RecursionAvailable = true
	}
	return res
}

func (h *EntryHandler) responseNXDomain(req *dns.Msg) *dns.Msg {
	res := new(dns.Msg)
	res.SetReply(req)
	res.Rcode = dns.RcodeNameError
	if h.opts.RecursionAvailable {
		res.RecursionAvailable = true
	}
	return res
}

var preRejectValidChar = [256]bool{
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
