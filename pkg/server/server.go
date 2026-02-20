package server

import (
	"errors"
	"io"
	"sync"
	"time"

	"go.uber.org/zap"

	D "github.com/pmkol/mosdns-x/pkg/server/dns_handler"
	H "github.com/pmkol/mosdns-x/pkg/server/http_handler"
)

var (
	ErrServerClosed       = errors.New("server closed")
	errMissingHTTPHandler = errors.New("missing http handler")
	errMissingDNSHandler  = errors.New("missing dns handler")
)

var nopLogger = zap.NewNop()

type ServerOpts struct {
	// Logger optionally specifies a logger for the server logging.
	// A nil Logger will disable the logging.
	Logger *zap.Logger

	// DNSHandler is the dns handler required by UDP, TCP, DoT server.
	DNSHandler D.Handler

	// HttpHandler is the http handler required by HTTP, DoH server.
	HttpHandler *H.Handler

	// Certificate files to start DoT, DoH server.
	Cert, Key string

	// KernelTX and KernelRX control whether kernel TLS offloading is enabled.
	KernelRX, KernelTX bool

	// IdleTimeout limits the maximum time period that a connection can idle.
	IdleTimeout time.Duration
}

func (opts *ServerOpts) init() {
	if opts.Logger == nil {
		opts.Logger = nopLogger
	}

	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 0
	}
}

type Server struct {
	opts ServerOpts

	m             sync.Mutex
	closed        bool
	closerTracker map[io.Closer]struct{}
	wg            sync.WaitGroup
}

func NewServer(opts ServerOpts) *Server {
	opts.init()
	return &Server{
		opts: opts,
	}
}

// Closed returns true if server was closed.
func (s *Server) Closed() bool {
	s.m.Lock()
	defer s.m.Unlock()
	return s.closed
}

// trackCloser adds or removes c to the Server and return true if Server is not closed.
func (s *Server) trackCloser(c io.Closer, add bool) bool {
	s.m.Lock()
	defer s.m.Unlock()

	if s.closerTracker == nil {
		s.closerTracker = make(map[io.Closer]struct{})
	}

	if add {
		if s.closed {
			return false
		}
		s.closerTracker[c] = struct{}{}
	} else {
		delete(s.closerTracker, c)
	}
	return true
}

// Close closes the Server and all its inner listeners.
func (s *Server) Close() {
	s.m.Lock()
	if s.closed {
		s.m.Unlock()
		return
	}

	s.closed = true

	// Copy all closers to a temporary slice to avoid holding the lock during Close() operations.
	// This prevents potential deadlocks if a closer's Close method calls back into the server.
	closers := make([]io.Closer, 0, len(s.closerTracker))
	for c := range s.closerTracker {
		closers = append(closers, c)
	}

	// Clear the tracker map and release the lock immediately.
	s.closerTracker = nil
	s.m.Unlock()

	// Execute Close() on each tracker outside of the lock.
	for _, c := range closers {
		_ = c.Close()
	}

	// Wait for all server goroutines to exit.
	s.wg.Wait()
}
