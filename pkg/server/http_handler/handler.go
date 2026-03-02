package http_handler

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
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
	// Cache interface calls and common components for performance
	u := req.URL()
	hdr := req.Header()
	method := req.Method()
	path := u.Path

	// Address resolution and metadata initialization
	addr, _ := getRemoteAddr(req, h.opts.SrcIPHeader)
	// CAPTURE remoteAddr after potential SetRemoteAddr in getRemoteAddr for accurate logging
	remoteAddr := req.GetRemoteAddr() 
	meta := C.NewRequestMeta(addr)

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
	if h.opts.HealthPath != "" && path == h.opts.HealthPath {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		return
	}

	// 2. Path & Root validation
	if (h.opts.Path != "" && path != h.opts.Path) || path == "/" {
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

	switch method {
	case http.MethodGet:
		// RFC 8484 compliance: Check if Accept header contains the media type
		if !strings.Contains(hdr.Get("Accept"), "application/dns-message") {
			if h.opts.RedirectURL != "" {
				w.Header().Set("Location", h.opts.RedirectURL)
				w.WriteHeader(http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

        // Manually parse RawQuery to avoid url.ParseQuery allocation; use PathUnescape for safe % decoding
		s := rawQueryGet(u.RawQuery, "dns")
		if s == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if base64.RawURLEncoding.DecodedLen(len(s)) > dns.MaxMsgSize {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}

		b, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			h.opts.Logger.Warn("decode base64 failed", zap.String("from", remoteAddr), zap.Error(err))
			return
		}

	case http.MethodPost:
		if hdr.Get("Content-Type") != "application/dns-message" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// IMPORTANT: Read up to MaxMsgSize+1 bytes using LimitReader.
		// Previously used pool.GetBuf(dns.MaxMsgSize+1) = 65537 bytes which
		// exceeded the Allocator's max slab class, causing 30GB+ of allocations
		// with zero pool reuse. DNS messages in practice are 50–4096 bytes,
		// so the runtime allocator handles these efficiently.
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

	// DNS Processing
	m := pool.GetMsg()
	defer pool.ReleaseMsg(m)
	if err := m.Unpack(b); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.opts.Logger.Warn("unpack dns msg failed", zap.String("from", remoteAddr), zap.Error(err))
		return
	}

	r, err := h.opts.DNSHandler.ServeDNS(req.Context(), m, meta)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.opts.Logger.Warn("dns handler error", zap.String("from", remoteAddr), zap.Error(err))
		return
	}

	// Reduce GC pressure by using the message pool for packing the response
	resBytes, buf, err := pool.PackBuffer(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.opts.Logger.Warn("pack response failed", zap.String("from", remoteAddr), zap.Error(err))
		return
	}
	defer buf.Release()

	// Finalize Response
	respHdr := w.Header()
	respHdr.Set("Content-Type", "application/dns-message")
	respHdr.Set("Cache-Control", "max-age="+strconv.Itoa(int(dnsutils.GetMinimalTTL(r))))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resBytes)
}

func rawQueryGet(rawQuery, key string) string {
	for rawQuery != "" {
		var part string
		part, rawQuery, _ = strings.Cut(rawQuery, "&")
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if k == key {
			decoded, err := url.PathUnescape(v)
			if err != nil {
				return v
			}
			return decoded
		}
	}
	return ""
}

func getRemoteAddr(req Request, customHeader string) (netip.Addr, error) {
	hdr := req.Header()
	for _, h := range proxyHeaders {
		if val := hdr.Get(h); val != "" {
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

	if customHeader != "" {
		if val := hdr.Get(customHeader); val != "" {
			if addr, err := netip.ParseAddr(val); err == nil {
				req.SetRemoteAddr(val)
				return addr, nil
			}
		}
	}

	addrport, err := netip.ParseAddrPort(req.GetRemoteAddr())
	if err != nil {
		return netip.Addr{}, err
	}
	return addrport.Addr(), nil
}
