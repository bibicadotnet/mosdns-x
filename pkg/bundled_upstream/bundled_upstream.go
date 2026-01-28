/*
 * Copyright (C) 2020-2022, IrineSistiana
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

package bundled_upstream

import (
	"context"
	"errors"
	"sync"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/query_context"
)

type Upstream interface {
	// Exchange sends q to the upstream and waits for response.
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)

	// Trusted indicates whether this Upstream is trusted/reliable.
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

// getRcodePriority returns priority for non-success DNS response codes.
// Lower score = higher priority.
// Note: RcodeSuccess (0) is handled separately and returns immediately,
// so it doesn't need a priority score here.
func getRcodePriority(rcode int) int {
	switch rcode {
	case dns.RcodeNameError:
		return 1 // NXDOMAIN - definitive "not exist"
	case dns.RcodeServerFailure:
		return 2 // SERVFAIL - temporary issue
	case dns.RcodeRefused:
		return 3 // REFUSED - policy block
	default:
		return 4 // Other errors
	}
}

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

	var lastRes *dns.Msg
	var lastErr error

	for res := range c {
		if res.err != nil {
			// Only log if the error is not a result of a purposeful cancellation
			if !errors.Is(res.err, context.Canceled) {
				logger.Warn("upstream failed detail",
					qCtx.InfoField(),
					zap.String("addr", res.from.Address()),
					zap.Error(res.err))
				lastErr = res.err
			}
			continue
		}

		if res.r == nil {
			continue
		}

		// Priority 1: Trusted upstream or Successful Rcode (0) - Return immediately
		if res.from.Trusted() || res.r.Rcode == dns.RcodeSuccess {
			cancel() // Terminate other pending requests
			return res.r, nil
		}

		// Priority 2: Deterministic Hierarchy for error responses (e.g., NXDOMAIN > SERVFAIL)
		if lastRes == nil || getRcodePriority(res.r.Rcode) < getRcodePriority(lastRes.Rcode) {
			lastRes = res.r
		}
	}

	// Fallback to the best available error response found during the parallel execution
	if lastRes != nil {
		return lastRes, nil
	}

	// Return the last network error if no valid DNS responses were received (ignoring cancel)
	if lastErr != nil && !errors.Is(lastErr, context.Canceled) {
		return nil, lastErr
	}

	return nil, ErrAllFailed
}
