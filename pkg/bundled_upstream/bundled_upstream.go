/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 */

package bundled_upstream

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/query_context"
)

type Upstream interface {
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
	Trusted() bool
	Address() string
}

type parallelResult struct {
	r    *dns.Msg
	err  error
	from Upstream
}

var nopLogger = zap.NewNop()
var ErrAllFailed = errors.New("all upstreams failed")

func ExchangeParallel(ctx context.Context, qCtx *query_context.Context, upstreams []Upstream, logger *zap.Logger) (*dns.Msg, error) {
	if logger == nil {
		logger = nopLogger
	}

	t := len(upstreams)
	if t == 0 {
		return nil, ErrAllFailed
	}

	q := qCtx.Q()
	if t == 1 {
		return upstreams[0].Exchange(ctx, q)
	}

	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	c := make(chan *parallelResult, t)

	for _, u := range upstreams {
		u := u
		qCopy := q.Copy()
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := u.Exchange(taskCtx, qCopy)
			select {
			case c <- &parallelResult{r: r, err: err, from: u}:
			case <-taskCtx.Done():
				return
			}
		}()
	}

	go func() {
		wg.Wait()
		close(c)
	}()

	var errMsgs []string
	var trustedResponse *dns.Msg

	for res := range c {
		if res.err != nil {
			if errors.Is(res.err, context.Canceled) || errors.Is(res.err, context.DeadlineExceeded) {
				logger.Debug("upstream canceled or timed out",
					qCtx.InfoField(),
					zap.String("addr", res.from.Address()))
			} else {
				logger.Warn("upstream exchange failed",
					qCtx.InfoField(),
					zap.String("addr", res.from.Address()),
					zap.Error(res.err))
			}

			if !errors.Is(res.err, context.Canceled) && !errors.Is(res.err, context.DeadlineExceeded) {
				errMsgs = append(errMsgs, fmt.Sprintf("[%s: %v]", res.from.Address(), res.err))
			}
			continue
		}

		if res.r == nil {
			continue
		}

		// ANY upstream with SUCCESS → Return immediately
		if res.r.Rcode == dns.RcodeSuccess {
			cancel()
			return res.r, nil
		}

		// Trusted upstream with error response → Save for fallback
		if res.from.Trusted() {
			trustedResponse = res.r
			errMsgs = append(errMsgs, fmt.Sprintf("[%s: rcode %s]", res.from.Address(), dns.RcodeToString[res.r.Rcode]))
		} else {
			// Untrusted upstream with error response → Discard
			logger.Debug("discarded untrusted error response",
				qCtx.InfoField(),
				zap.String("addr", res.from.Address()),
				zap.String("rcode", dns.RcodeToString[res.r.Rcode]))
			errMsgs = append(errMsgs, fmt.Sprintf("[%s: rcode %s]", res.from.Address(), dns.RcodeToString[res.r.Rcode]))
		}
	}

	// No SUCCESS found, return trusted error response if available
	if trustedResponse != nil {
		return trustedResponse, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var detailedErr error
	if len(errMsgs) > 0 {
		detailedErr = errors.New("all upstreams failed: " + strings.Join(errMsgs, ", "))
	} else {
		detailedErr = ErrAllFailed
	}

	logger.Warn("parallel exchange failed",
		qCtx.InfoField(),
		zap.Error(detailedErr))

	return nil, detailedErr
}
