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

package server

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	H "github.com/pmkol/mosdns-x/pkg/server/http_handler"
)

const (
	defaultQUICIdleTimeout = 30 * time.Second

	// DoH over HTTP/3 limits
	maxDoHBodySize        = 64 * 1024 // RFC 8484 / EDNS0
	maxDoH3HeaderBytes    = 4096
	maxConcurrentDoH3Reqs = 2048
)

// Limit concurrent DoH3 requests (stream-level protection)
var doh3Semaphore = make(chan struct{}, maxConcurrentDoH3Reqs)

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
		Handler:        &sHandler{s.opts.HttpHandler},
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: maxDoH3HeaderBytes,
	}

	if ok := s.trackCloser(hs, true); !ok {
		return ErrServerClosed
	}
	defer s.trackCloser(hs, false)

	err := hs.ServeListener(l)
	if err == http.ErrServerClosed {
		return ErrServerClosed
	}
	return err
}

type sHandler struct {
	h *H.Handler
}

func (h *sHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Limit concurrent DoH3 requests
	select {
	case doh3Semaphore <- struct{}{}:
		defer func() { <-doh3Semaphore }()
	default:
		http.Error(w, "Server Busy", http.StatusTooManyRequests)
		return
	}

	// 2. Limit POST body size (HTTP-level protection)
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxDoHBodySize)
	}

	h.h.ServeHTTP(&sWriter{w}, &sRequest{r})
}

type sRequest struct {
	r *http.Request
}

func (r *sRequest) URL() *url.URL {
	return r.r.URL
}

func (r *sRequest) TLS() *H.TlsInfo {
	if r.r.TLS == nil {
		return nil
	}
	return &H.TlsInfo{
		Version:            r.r.TLS.Version,
		ServerName:         r.r.TLS.ServerName,
		NegotiatedProtocol: r.r.TLS.NegotiatedProtocol,
	}
}

func (r *sRequest) Body() io.ReadCloser {
	// Body already limited at HTTP layer
	return r.r.Body
}

func (r *sRequest) Header() H.Header {
	return r.r.Header
}

func (r *sRequest) Method() string {
	return r.r.Method
}

func (r *sRequest) Context() context.Context {
	return r.r.Context()
}

func (r *sRequest) RequestURI() string {
	return r.r.RequestURI
}

func (r *sRequest) GetRemoteAddr() string {
	return r.r.RemoteAddr
}

func (r *sRequest) SetRemoteAddr(addr string) {
	r.r.RemoteAddr = addr
}

type sWriter struct {
	w http.ResponseWriter
}

func (w *sWriter) Header() H.Header {
	return w.w.Header()
}

func (w *sWriter) Write(b []byte) (int, error) {
	return w.w.Write(b)
}

func (w *sWriter) WriteHeader(statusCode int) {
	w.w.WriteHeader(statusCode)
}
