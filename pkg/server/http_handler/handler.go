/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 */

package http_handler

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/pool"
	C "github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/server/dns_handler"
)

var nopLogger = zap.NewNop()

// proxyHeaders is defined as a package-level variable to avoid allocation on every request.
var proxyHeaders = []string{"True-Client-IP", "X-Real-IP", "X-Forwarded-For"}

type HandlerOpts struct {
	DNSHandler  dns_handler.Handler
	Path        string
	SrcIPHeader string
	HealthPath  string
	RedirectURL string
	Logger      *zap.Logger
}

func (opts *HandlerOpts) Init() error {
	if opts.DNSHandler == nil {
		return errors.New("nil dns handler")
	}
	if opts.Logger == nil {
		opts.Logger = nopLogger
	}
	if opts.HealthPath == "" {
		opts.HealthPath = "/health"
	}
	return nil
}

type Handler struct {
	opts HandlerOpts
}

func NewHandler(opts HandlerOpts) (*Handler, error) {
	if err := opts.Init(); err != nil {
		return nil, err
	}
	return &Handler{opts: opts}, nil
}

func (h *Handler) warnErr(req Request, err error) {
	h.opts.Logger.Warn(err.Error(), zap.String("from", req.GetRemoteAddr()), zap.String("method", req.Method()), zap.String("url", req.RequestURI()))
}

// Interfaces to abstract http/http3 requests
type ResponseWriter interface {
	Header() Header
	Write([]byte) (int, error)
	WriteHeader(statusCode int)
}

type Header interface {
	Get(key string) string
	Set(key string, value string)
}

type Request interface {
	URL() *url.URL
	TLS() *TlsInfo
	Body() io.ReadCloser
	Header() Header
	Method() string
	Context() context.Context
	RequestURI() string
	GetRemoteAddr() string
	SetRemoteAddr(addr string)
}

type TlsInfo struct {
	Version            uint16
	ServerName         string
	NegotiatedProtocol string
}

func (h *Handler) ServeHTTP(w ResponseWriter, req Request) {
	// Initialize RequestMeta with proper IP unmapping (IPv4-in-IPv6 support)
	meta := new(C.RequestMeta)
	if addr, err := getRemoteAddr(req, h.opts.SrcIPHeader); err == nil {
		meta.SetClientAddr(addr)
	}

	if tlsInfo := req.TLS(); tlsInfo != nil {
		meta.SetServerName(tlsInfo.ServerName)
		switch tlsInfo.NegotiatedProtocol {
		case http3.NextProtoH3:
			meta.SetProtocol(C.ProtocolH3)
		case "h2":
			meta.SetProtocol(C.ProtocolH2)
		default:
			meta.SetProtocol(C.ProtocolHTTPS)
		}
	} else {
		meta.SetProtocol(C.ProtocolHTTP)
	}

	// 1. Health check - Fast path
	if h.opts.HealthPath != "" && req.URL().Path == h.opts.HealthPath {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		return
	}

	// 2. Path & Root validation - Anti-scanner redirection
	if (len(h.opts.Path) != 0 && req.URL().Path != h.opts.Path) || req.URL().Path == "/" {
		if h.opts.RedirectURL != "" {
			w.Header().Set("Location", h.opts.RedirectURL)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var b []byte
	var err error

	switch req.Method() {
	case http.MethodGet:
		// 3. GET validation - RFC 8484 compliance
		accept := req.Header().Get("Accept")
		matched := false
		for _, v := range strings.Split(accept, ",") {
			mediatype := strings.TrimSpace(strings.SplitN(v, ";", 2)[0])
			if mediatype == "application/dns-message" {
				matched = true
				break
			}
		}

		if !matched {
			if h.opts.RedirectURL != "" {
				w.Header().Set("Location", h.opts.RedirectURL)
				w.WriteHeader(http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		s := req.URL().Query().Get("dns")
		if len(s) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Security: Pre-check decoded length to prevent oversized memory allocation
		if base64.RawURLEncoding.DecodedLen(len(s)) > dns.MaxMsgSize {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}

		b, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			h.warnErr(req, fmt.Errorf("decode base64 failed: %w", err))
			return
		}

	case http.MethodPost:
		// 4. POST validation - Strict RFC 8484
		if contentType := req.Header().Get("Content-Type"); contentType != "application/dns-message" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Security: Use LimitReader to prevent OOM from malicious large bodies
		b, err = io.ReadAll(io.LimitReader(req.Body(), dns.MaxMsgSize+1))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(b) > dns.MaxMsgSize {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 5. DNS Processing
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.warnErr(req, fmt.Errorf("unpack dns msg failed: %w", err))
		return
	}

	r, err := h.opts.DNSHandler.ServeDNS(req.Context(), m, meta)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.warnErr(req, fmt.Errorf("dns handler error: %w", err))
		return
	}

	// Use pool to pack response, reducing GC pressure
	resBytes, buf, err := pool.PackBuffer(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.warnErr(req, fmt.Errorf("pack response failed: %w", err))
		return
	}
	defer buf.Release()

	// 6. Finalize Response
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", dnsutils.GetMinimalTTL(r)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resBytes)
}

func getRemoteAddr(req Request, customHeader string) (netip.Addr, error) {
	// Priority check for common proxy headers using the static package-level slice
	for _, h := range proxyHeaders {
		if val := req.Header().Get(h); val != "" {
			// Handle potential list in X-Forwarded-For (take first)
			ipStr := val
			if h == "X-Forwarded-For" {
				ipStr, _, _ = strings.Cut(val, ",")
			}
			ipStr = strings.TrimSpace(ipStr)
			if addr, err := netip.ParseAddr(ipStr); err == nil {
				req.SetRemoteAddr(ipStr)
				return addr, nil
			}
		}
	}

	// Check custom header if provided and not already checked
	if customHeader != "" {
		isStandard := false
		for _, h := range proxyHeaders {
			if strings.EqualFold(customHeader, h) {
				isStandard = true
				break
			}
		}
		if !isStandard {
			if val := req.Header().Get(customHeader); val != "" {
				if addr, err := netip.ParseAddr(val); err == nil {
					req.SetRemoteAddr(val)
					return addr, nil
				}
			}
		}
	}

	// Fallback to direct remote address
	addrport, err := netip.ParseAddrPort(req.GetRemoteAddr())
	if err != nil {
		return netip.Addr{}, err
	}
	return addrport.Addr(), nil
}
