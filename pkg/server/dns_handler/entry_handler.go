/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 */

package dns_handler

import (
	"context"
	"errors"
	"fmt"
	"testing"
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

// NewEntryHandler returns Handler interface directly (Option A - Standard)
func NewEntryHandler(opts EntryHandlerOpts) (Handler, error) {
	if err := opts.Init(); err != nil {
		return nil, err
	}
	return &EntryHandler{opts: opts}, nil
}

func (h *EntryHandler) ServeDNS(ctx context.Context, req *dns.Msg, meta *query_context.RequestMeta) (*dns.Msg, error) {
	// 1. Setup Query-level isolation context
	qCtx, cancel := context.WithTimeout(ctx, h.opts.QueryTimeout)
	defer cancel()

	// 2. FormError checks
	if len(req.Question) == 0 {
		h.opts.Logger.Debug("request has zero question", zap.Stringer("from", meta.ClientAddr()))
		return h.responseFormErr(req), nil
	}
	for _, question := range req.Question {
		if _, ok := dns.IsDomainName(question.Name); !ok {
			h.opts.Logger.Debug("invalid question name", zap.String("name", question.Name))
			return h.responseFormErr(req), nil
		}
	}

	origID := req.Id
	queryCtx := query_context.NewContext(req, meta)

	// 3. Execute Pipeline with isolated context
	// Verified signature: Exec(ctx context.Context, qCtx *query_context.Context, next Executable) error
	err := h.opts.Entry.Exec(qCtx, queryCtx, nil)
	respMsg := queryCtx.R()

	// 4. Smart Logging (Downgrade expected network/timeout errors)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			h.opts.Logger.Debug("query interrupted", queryCtx.InfoField(), zap.Error(err))
		} else {
			h.opts.Logger.Warn("entry returned an err", queryCtx.InfoField(), zap.Error(err))
		}
	}

	// 5. Fallback Response Logic
	if respMsg == nil {
		if err == nil {
			h.opts.Logger.Error("entry returned with nil response", queryCtx.InfoField())
		}
		
		respMsg = new(dns.Msg)
		respMsg.SetReply(req)
		
		if err != nil {
			respMsg.Rcode = dns.RcodeServerFailure // SERVFAIL for upstream/timeout issues
		} else {
			respMsg.Rcode = dns.RcodeRefused       // REFUSED for plugin logic gaps
		}
	}

	// 6. Final headers
	if h.opts.RecursionAvailable {
		respMsg.RecursionAvailable = true
	}
	respMsg.Id = origID

	// Always return nil error to keep the connection alive (Sequential/DoH/DoQ friendly)
	return respMsg, nil
}

func (h *EntryHandler) responseFormErr(req *dns.Msg) *dns.Msg {
	res := new(dns.Msg)
	res.SetReply(req)
	res.Rcode = dns.RcodeFormatError
	if h.opts.RecursionAvailable {
		res.RecursionAvailable = true
	}
	return res
}

// DummyServerHandler for testing
type DummyServerHandler struct {
	T       *testing.T
	WantMsg *dns.Msg
	WantErr error
}

func (d *DummyServerHandler) ServeDNS(_ context.Context, req *dns.Msg, meta *query_context.RequestMeta) (*dns.Msg, error) {
	if d.WantErr != nil {
		return nil, d.WantErr
	}
	var resp *dns.Msg
	if d.WantMsg != nil {
		resp = d.WantMsg.Copy()
		resp.Id = req.Id
	} else {
		resp = new(dns.Msg)
		resp.SetReply(req)
	}
	return resp, nil
}
