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
 * along with this program.  See the <https://www.gnu.org/licenses/>.
 */

package server

import (
	"context"
	"fmt"
	"net"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/pool"
	C "github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/server/dns_handler"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

// cmcUDPConn can read and write cmsg.
type cmcUDPConn interface {
	readFrom(b []byte) (n int, dst net.IP, IfIndex int, src net.Addr, err error)
	writeTo(b []byte, src net.IP, IfIndex int, dst net.Addr) (n int, err error)
}

func (s *Server) ServeUDP(c net.PacketConn) error {
	defer c.Close()

	handler := s.opts.DNSHandler
	if handler == nil {
		return errMissingDNSHandler
	}

	if ok := s.trackCloser(c, true); !ok {
		return ErrServerClosed
	}
	defer s.trackCloser(c, false)

	listenerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readBuf := pool.GetBuf(64 * 1024)
	defer readBuf.Release()
	rb := readBuf.Bytes()

	var cmc cmcUDPConn
	var err error
	uc, ok := c.(*net.UDPConn)
	if ok && uc.LocalAddr().(*net.UDPAddr).IP.IsUnspecified() {
		cmc, err = newCmc(uc)
		if err != nil {
			return fmt.Errorf("failed to control socket cmsg, %w", err)
		}
	} else {
		cmc = newDummyCmc(c)
	}

	for {
		n, localAddr, ifIndex, remoteAddr, err := cmc.readFrom(rb)
		if err != nil {
			if s.Closed() {
				return ErrServerClosed
			}
			return fmt.Errorf("unexpected read err: %w", err)
		}
		clientAddr := utils.GetAddrFromAddr(remoteAddr)

		q := new(dns.Msg)
		if err := q.Unpack(rb[:n]); err != nil {
			s.opts.Logger.Warn("invalid msg", zap.Error(err), zap.Binary("msg", rb[:n]), zap.Stringer("from", remoteAddr))
			continue
		}

		// handle query
		go func() {
			meta := C.NewRequestMeta(clientAddr)
			meta.SetProtocol(C.ProtocolUDP)
			qCtx := C.NewContext(q, meta)

			var err error
			// 🚀 Kích hoạt làn đường ưu tiên cho Zero-Unpack
			if rawH, ok := handler.(dns_handler.RawHandler); ok {
				err = rawH.ServeDNSRaw(listenerCtx, qCtx)
			} else {
				// Fallback Legacy Path cho các plugin cũ
				r, e := handler.ServeDNS(listenerCtx, q, meta)
				err = e
				if r != nil {
					qCtx.SetResponse(r)
				}
			}

			if err != nil {
				s.opts.Logger.Warn("handler err", zap.Error(err))
				return
			}

			// ===== FAST PATH (Zero-Unpack) =====
			// Gửi thẳng bytes thô. Business logic (ID, RA, TC, TTL) do Plugin xử lý.
			if raw := qCtx.RawR(); raw != nil {
				if _, err := cmc.writeTo(raw, localAddr, ifIndex, remoteAddr); err != nil {
					s.opts.Logger.Warn("failed to write raw response", zap.Stringer("client", remoteAddr), zap.Error(err))
				}
				qCtx.ReleaseRawR()
				return
			}

			// ===== LEGACY PATH =====
			// Dành cho các plugin vẫn trả về dns.Msg
			if r := qCtx.R(); r != nil {
				r.Id = q.Id // Đảm bảo ID khớp cho legacy plugin
				r.Truncate(getUDPSize(q))

				b, buf, err := pool.PackBuffer(r)
				if err != nil {
					s.opts.Logger.Error("failed to pack handler's response", zap.Error(err), zap.Stringer("msg", r))
					return
				}
				
				if _, err := cmc.writeTo(b, localAddr, ifIndex, remoteAddr); err != nil {
					s.opts.Logger.Warn("failed to write response", zap.Stringer("client", remoteAddr), zap.Error(err))
				}
				buf.Release()
			}
		}()
	}
}

func getUDPSize(m *dns.Msg) int {
	var s uint16
	if opt := m.IsEdns0(); opt != nil {
		s = opt.UDPSize()
	}
	if s < dns.MinMsgSize {
		s = dns.MinMsgSize
	}
	return int(s)
}

func newDummyCmc(c net.PacketConn) cmcUDPConn {
	return dummyCmcWrapper{c: c}
}

type dummyCmcWrapper struct {
	c net.PacketConn
}

func (w dummyCmcWrapper) readFrom(b []byte) (n int, dst net.IP, IfIndex int, src net.Addr, err error) {
	n, src, err = w.c.ReadFrom(b)
	return
}

func (w dummyCmcWrapper) writeTo(b []byte, src net.IP, IfIndex int, dst net.Addr) (n int, err error) {
	return w.c.WriteTo(b, dst)
}
