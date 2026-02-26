package server

import (
	"errors"
	"time"

	"go.uber.org/zap"

	D "github.com/pmkol/mosdns-x/pkg/server/dns_handler"
	H "github.com/pmkol/mosdns-x/pkg/server/http_handler"
)

var (
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
}

func NewServer(opts ServerOpts) *Server {
	opts.init()
	return &Server{
		opts: opts,
	}
}
