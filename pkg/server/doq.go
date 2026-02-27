package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/pool"
	C "github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

type quicCloser struct {
	closed atomic.Bool
	conn   *quic.Conn
}

func (c *quicCloser) Close() error {
	return c.close(1)
}

func (c *quicCloser) close(code quic.ApplicationErrorCode) error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	return c.conn.CloseWithError(code, "")
}

func (s *Server) ServeQUIC(l *quic.EarlyListener) error {
	defer l.Close()

	handler := s.opts.DNSHandler
	if handler == nil {
		return errMissingDNSHandler
	}

	listenerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		c, err := l.Accept(listenerCtx)
		if err != nil {
			return fmt.Errorf("unexpected listener err: %w", err)
		}

		quicConnCtx, cancelConn := context.WithCancel(listenerCtx)
		closer := &quicCloser{conn: c}

		go func() {
			defer closer.close(0)
			defer cancelConn()

			clientAddr := utils.GetAddrFromAddr(c.RemoteAddr())
			meta := C.NewRequestMeta(clientAddr)
			meta.SetProtocol(C.ProtocolQUIC)
			meta.SetServerName(c.ConnectionState().TLS.ServerName)

			// Idle timeout và first-read timeout được quản lý hoàn toàn bởi
			// quic-go qua MaxIdleTimeout trong quic.Config (cấu hình ở tls.go).
			// Không cần timer thủ công ở đây.

			for {
				stream, err := c.AcceptStream(quicConnCtx)
				if err != nil {
					if quicConnCtx.Err() != nil {
						return
					}
					closer.close(1)
					return
				}

				go func() {
					readDone := false
					defer func() {
						if !readDone {
							stream.CancelRead(0)
						}
					}()
					defer stream.Close()

					req := pool.GetMsg()
					defer pool.ReleaseMsg(req)

					_, err := dnsutils.ReadMsgFromTCP(stream, req)
					if err != nil {
						stream.CancelRead(1)
						stream.CancelWrite(1)
						readDone = true
						return
					}

					readDone = true

					if req.Id != 0 {
						stream.CancelWrite(1)
						closer.close(1)
						return
					}

					r, err := handler.ServeDNS(quicConnCtx, req, meta)
					if err != nil {
						stream.CancelWrite(1)
						s.opts.Logger.Debug("handler err", zap.Error(err))
						return
					}

					b, buf, err := pool.PackBuffer(r)
					if err != nil {
						stream.CancelWrite(1)
						s.opts.Logger.Error("failed to pack handler's response", zap.Error(err), zap.Stringer("msg", r))
						return
					}
					defer buf.Release()

					if _, err := dnsutils.WriteRawMsgToTCP(stream, b); err != nil {
						stream.CancelWrite(1)
						errStr := err.Error()
						if errors.Is(err, context.Canceled) || strings.Contains(errStr, "0x1") {
							return
						}
						s.opts.Logger.Debug("failed to write response", zap.Stringer("client", c.RemoteAddr()), zap.Error(err))
					}
				}()
			}
		}()
	}
}
