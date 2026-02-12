/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 */

package dns_handler

import (
	"context"
	"errors"
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

// RawHandler defines a high-performance interface for Zero-Unpack processing.
type RawHandler interface {
	ServeDNSRaw(ctx context.Context, qCtx *query_context.Context) error
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

// ServeDNSRaw implements the RawHandler interface.
// It is a pure execution pipe without validation or timeout logic.
func (h *EntryHandler) ServeDNSRaw(ctx context.Context, qCtx *query_context.Context) error {
	return h.opts.Entry.Exec(ctx, qCtx, nil)
}

// ServeDNS is the legacy entry point with full validation and timeout management.
func (h *EntryHandler) ServeDNS(ctx context.Context, req *dns.Msg, meta *query_context.RequestMeta) (*dns.Msg, error) {
	// 1. Independent per-query timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, h.opts.QueryTimeout)
	defer cancel()

	// 2. Request Validation
	if len(req.Question) == 0 {
		h.opts.Logger.Debug("request has zero question")
		return h.responseFormErr(req), nil
	}
	for _, question := range req.Question {
		if _, ok := dns.IsDomainName(question.Name); !ok {
			h.opts.Logger.Debug("invalid question name", zap.String("name", question.Name))
			return h.responseFormErr(req), nil
		}
	}

	queryCtx := query_context.NewContext(req, meta)

	// 3. Call the raw execution pipe
	err := h.ServeDNSRaw(timeoutCtx, queryCtx)

	// 4. Logging behavior restored to original
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			h.opts.Logger.Debug("query interrupted", queryCtx.InfoField(), zap.Error(err))
		} else {
			h.opts.Logger.Warn("entry returned an err", queryCtx.InfoField(), zap.Error(err))
		}
	}

	respMsg := queryCtx.R()

	// 5. Legacy Raw Fallback: If plugin set RawR but server needs *dns.Msg
	if respMsg == nil {
		if raw := queryCtx.RawR(); raw != nil {
			respMsg = new(dns.Msg)
			if unpackErr := respMsg.Unpack(raw); unpackErr != nil {
				h.opts.Logger.Error("failed to unpack rawR in legacy path", zap.Error(unpackErr))
				respMsg = nil
			} else {
				// Immediate ID patch for safety
				respMsg.Id = req.Id
			}
			queryCtx.ReleaseRawR()
		}
	}

	// 6. Finalization & Safety
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
	respMsg.Id = req.Id // Final safety re-patch

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
