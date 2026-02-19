/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 */

package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"gitlab.com/go-extension/tls"
	"go.uber.org/zap"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/pool"
	C "github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/server/dns_handler"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

type TCPConn struct {
	sync.Mutex
	net.Conn
	handler dns_handler.Handler
	meta    *C.RequestMeta
}

func (c *TCPConn) ServeDNS(ctx context.Context, req *dns.Msg) (*dns.Msg, []byte, error) {
	return c.handler.ServeDNS(ctx, req, c.meta)
}

func (c *TCPConn) WriteRawMsg(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()
	return dnsutils.WriteRawMsgToTCP(c, b)
}

const (
	defaultTCPIdleTimeout = time.Second * 10
	tcpFirstReadTimeout   = time.Millisecond * 500
)

func (s *Server) ServeTCP(l net.Listener) error {
	defer l.Close()

	handler := s.opts.DNSHandler
	if handler == nil {
		return errMissingDNSHandler
	}

	if ok := s.trackCloser(l, true); !ok {
		return ErrServerClosed
	}
	defer s.trackCloser(l, false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for {
		c, err := l.Accept()
		if err != nil {
			if s.Closed() {
				return ErrServerClosed
			}
			// Only continue if it's a net.Error timeout.
			// Other fatal errors return to let the supervisor restart the process.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("unexpected listener err: %w", err)
		}

		go s.handleConnectionTcp(ctx, &TCPConn{Conn: c, handler: handler})
	}
}

func (s *Server) handleConnectionTcp(ctx context.Context, c *TCPConn) {
	defer c.Close()

	if !s.trackCloser(c, true) {
		return
	}
	defer s.trackCloser(c, false)

	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	clientAddr := utils.GetAddrFromAddr(c.RemoteAddr())
	meta := C.NewRequestMeta(clientAddr)

	protocol := C.ProtocolTCP
	if tlsConn, ok := c.Conn.(*tls.Conn); ok {
		handshakeTimeout := s.opts.IdleTimeout
		if handshakeTimeout <= 0 {
			handshakeTimeout = defaultTCPIdleTimeout
		}

		handshakeCtx, cancel := context.WithTimeout(connCtx, handshakeTimeout)
		defer cancel()

		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			s.opts.Logger.Debug("handshake failed", zap.Stringer("from", c.RemoteAddr()), zap.Error(err))
			return
		}

		meta.SetServerName(tlsConn.ConnectionState().ServerName)
		protocol = C.ProtocolTLS
	}
	meta.SetProtocol(protocol)
	c.meta = meta

	idleTimeout := s.opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultTCPIdleTimeout
	}

	// Use Go 1.21+ built-in min
	c.SetReadDeadline(time.Now().Add(min(idleTimeout, tcpFirstReadTimeout)))

	for {
		req, rawReq, _, err := dnsutils.ReadMsgFromTCP(c.Conn)
		if err != nil {
			return
		}
		// We can use rawReq for zero-alloc if we pass it through.
		// For now, let's just use req.
		_ = rawReq

		go s.handleQueryTcp(connCtx, c, req, idleTimeout)

		c.SetReadDeadline(time.Now().Add(idleTimeout))
	}
}

func (s *Server) handleQueryTcp(ctx context.Context, c *TCPConn, req *dns.Msg, timeout time.Duration) {
	qCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	r, rawR, err := c.ServeDNS(qCtx, req)
	if err != nil {
		s.opts.Logger.Debug("handler err", zap.Error(err))
		return
	}

	if rawR != nil {
		_, err = c.WriteRawMsg(rawR)
		if err != nil {
			s.opts.Logger.Debug("failed to write response", zap.Stringer("client", c.RemoteAddr()), zap.Error(err))
		}
		return
	}

	b, buf, err := pool.PackBuffer(r)
	if err != nil {
		s.opts.Logger.Error("failed to unpack handler's response", zap.Error(err), zap.Stringer("msg", r))
		return
	}
	defer buf.Release()

	_, err = c.WriteRawMsg(b)
	if err != nil {
		s.opts.Logger.Debug("failed to write response", zap.Stringer("client", c.RemoteAddr()), zap.Error(err))
		return
	}
}
