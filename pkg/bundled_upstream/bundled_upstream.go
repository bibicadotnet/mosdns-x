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

const (
	priorityServFail = 0
	priorityOther    = 1
	priorityNoData   = 2
	priorityNXDomain = 3
)

// ExchangeParallel executes multiple DNS exchanges in parallel.
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
	var bestFallbackRes *dns.Msg
	var bestPrio = -1

	for res := range c {
		// === Phase 1: Network/Timeout Errors ===
		if res.err != nil {
			if errors.Is(res.err, context.Canceled) {
				logger.Debug("upstream exchange canceled", qCtx.InfoField(), zap.String("addr", res.from.Address()))
			} else {
				errMsgs = append(errMsgs, fmt.Sprintf("[%s: %v]", res.from.Address(), res.err))
				logger.Warn("upstream exchange failed", qCtx.InfoField(), zap.String("addr", res.from.Address()), zap.Error(res.err))
			}
			continue
		}

		if res.r == nil {
			continue
		}

		// === Phase 2: Success Racing (Fast Path) ===
		// Return immediately if any response has answer records.
		if res.r.Rcode == dns.RcodeSuccess && len(res.r.Answer) > 0 {
			cancel()
			return res.r, nil
		}

		// === Phase 3: Semantic Fallback Collection ===
		// If no answer yet, track the best non-answer response.
		newPrio := getResponsePriority(res.r)
		if bestFallbackRes == nil || newPrio > bestPrio {
			bestFallbackRes = res.r
			bestPrio = newPrio
		}

		// Log non-answer responses for debugging.
		status := getRcodeStatus(res.r)
		logger.Debug("upstream returned non-answer response",
			qCtx.InfoField(),
			zap.String("addr", res.from.Address()),
			zap.String("status", status))
	}

	// === Phase 4: Final Result Selection ===
	// 1. Best semantic error (NXDOMAIN > NODATA > SERVFAIL)
	if bestFallbackRes != nil {
		return bestFallbackRes, nil
	}

	// 2. Parent context termination (Timeout or Manual Cancel)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 3. All upstreams failed (Network errors)
	var detailedErr error
	if len(errMsgs) > 0 {
		detailedErr = fmt.Errorf("%w: %s", ErrAllFailed, strings.Join(errMsgs, ", "))
	} else {
		detailedErr = ErrAllFailed
	}

	logger.Warn("all upstreams failed completely", qCtx.InfoField(), zap.Error(detailedErr))
	return nil, detailedErr
}

func getResponsePriority(r *dns.Msg) int {
	switch r.Rcode {
	case dns.RcodeNameError:
		return priorityNXDomain
	case dns.RcodeSuccess:
		return priorityNoData
	case dns.RcodeServerFailure:
		return priorityServFail
	default:
		return priorityOther
	}
}

func getRcodeStatus(r *dns.Msg) string {
	if r.Rcode == dns.RcodeSuccess && len(r.Answer) == 0 {
		return "NODATA"
	}
	return dns.RcodeToString[r.Rcode]
}
