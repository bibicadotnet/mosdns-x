package server

import (
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const defaultQUICIdleTimeout = 30 * time.Second

func (s *Server) ServeH3(l *quic.EarlyListener) error {
	defer l.Close()

	if s.opts.HttpHandler == nil {
		return errMissingHTTPHandler
	}

	idleTimeout := s.opts.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultQUICIdleTimeout
	}

	hs := &http3.Server{
		Handler:        &httpHandlerWrapper{s},
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: 4096,
	}
	if ok := s.trackCloser(hs, true); !ok {
		return ErrServerClosed
	}
	defer s.trackCloser(hs, false)

	err := hs.ServeListener(l)
	if err == http.ErrServerClosed { // Replace http.ErrServerClosed with our ErrServerClosed
		return ErrServerClosed
	} else if err != nil {
		return err
	}
	return nil
}
