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

	// Rule: Use caller's context directly. Racing ends when the first success is found.
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

	errMsgs := make([]string, 0, t)
	var trustedResponse *dns.Msg

	for res := range c {
		if res.err != nil {
			// Rule: Distinguish between racing cancellation, timeout, and actual network errors.
			if errors.Is(res.err, context.Canceled) {
				logger.Debug("upstream exchange canceled (racing loser)",
					qCtx.InfoField(),
					zap.String("addr", res.from.Address()))
			} else if errors.Is(res.err, context.DeadlineExceeded) {
				logger.Warn("upstream exchange timed out",
					qCtx.InfoField(),
					zap.String("addr", res.from.Address()))
			} else {
				logger.Warn("upstream exchange failed",
					qCtx.InfoField(),
					zap.String("addr", res.from.Address()),
					zap.Bool("trusted", res.from.Trusted()),
					zap.Error(res.err))
				
				// Only aggregate errors from trusted upstreams to reduce log noise.
				if res.from.Trusted() {
					errMsgs = append(errMsgs, fmt.Sprintf("[%s: %v]", res.from.Address(), res.err))
				}
			}
			continue
		}

		if res.r == nil {
			continue
		}

		// Success-priority Rule: 
		// Return immediately ONLY if NOERROR and Answer is NOT empty.
		// This prevents accepting empty results (NODATA) prematurely.
		if res.r.Rcode == dns.RcodeSuccess && len(res.r.Answer) > 0 {
			cancel()
			return res.r, nil
		}

		// Fallback Rule: 
		// Deterministically keep the first trusted response (including NXDOMAIN/NODATA)
		// as a fallback if no "perfect" NOERROR response is received from others.
		if res.from.Trusted() && trustedResponse == nil {
			trustedResponse = res.r
			if res.r.Rcode != dns.RcodeSuccess {
				errMsgs = append(errMsgs, fmt.Sprintf("[%s: rcode %s]", res.from.Address(), dns.RcodeToString[res.r.Rcode]))
			}
		} else if !res.from.Trusted() {
			logger.Debug("discarded untrusted error response",
				qCtx.InfoField(),
				zap.String("addr", res.from.Address()),
				zap.String("rcode", dns.RcodeToString[res.r.Rcode]),
				zap.Bool("trusted", false))
		}
	}

	// No "Success + Answer" found. Return the first available trusted response.
	if trustedResponse != nil {
		return trustedResponse, nil
	}

	// Check if the entire process failed due to parent context deadline.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Use %w to wrap ErrAllFailed so callers can still use errors.Is().
	var detailedErr error
	if len(errMsgs) > 0 {
		detailedErr = fmt.Errorf("%w: %s", ErrAllFailed, strings.Join(errMsgs, ", "))
	} else {
		detailedErr = ErrAllFailed
	}

	logger.Warn("parallel exchange failed",
		qCtx.InfoField(),
		zap.Error(detailedErr))

	return nil, detailedErr
}
