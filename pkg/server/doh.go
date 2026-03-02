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
 */

package server

import (
	"net"
	"time"

	"gitlab.com/go-extension/http"
)

const (
	// TLS handshake + HTTP headers (Slowloris protection)
	defaultReadHeaderTimeout = 3 * time.Second

	// CRITICAL: protect against slow-read attacks (body + handler)
	defaultReadTimeout = 10 * time.Second

	// 2KB is sufficient for DoH (GET base64 + normal headers)
	defaultMaxHeaderBytes = 2048
)

func (s *Server) ServeHTTP(l net.Listener) error {
	defer l.Close()

	if s.opts.HttpHandler == nil {
		return errMissingHTTPHandler
	}

	idleTimeout := s.opts.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultTCPIdleTimeout
	}

	hs := &http.Server{
		Handler:           &eHttpHandlerWrapper{s},
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    defaultMaxHeaderBytes,
	}

	return hs.Serve(l)
}
