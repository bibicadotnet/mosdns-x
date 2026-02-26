package server

import (
	"context"
	"io"
	"net/http"
	"net/url"

	eHttp "gitlab.com/go-extension/http"

	H "github.com/pmkol/mosdns-x/pkg/server/http_handler"
)

// Standard net/http wrapper (used by DoH3)
type httpHandlerWrapper struct {
	s *Server
}

func (h *httpHandlerWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.s.opts.HttpHandler.ServeHTTP(&responseWriterWrapper{w}, &requestWrapper{r})
}

// gitlab.com/go-extension/http wrapper (used by DoH)
type eHttpHandlerWrapper struct {
	s *Server
}

func (h *eHttpHandlerWrapper) ServeHTTP(w eHttp.ResponseWriter, r *eHttp.Request) {
	h.s.opts.HttpHandler.ServeHTTP(&eResponseWriterWrapper{w}, &eRequestWrapper{r})
}

// Request wrappers
type requestWrapper struct{ r *http.Request }

func (r *requestWrapper) URL() *url.URL { return r.r.URL }
func (r *requestWrapper) TLS() *H.TlsInfo {
	if r.r.TLS == nil {
		return nil
	}
	return &H.TlsInfo{Version: r.r.TLS.Version, ServerName: r.r.TLS.ServerName, NegotiatedProtocol: r.r.TLS.NegotiatedProtocol}
}
func (r *requestWrapper) Body() io.ReadCloser       { return r.r.Body }
func (r *requestWrapper) Header() H.Header          { return r.r.Header }
func (r *requestWrapper) Method() string            { return r.r.Method }
func (r *requestWrapper) Context() context.Context  { return r.r.Context() }
func (r *requestWrapper) RequestURI() string        { return r.r.RequestURI }
func (r *requestWrapper) GetRemoteAddr() string     { return r.r.RemoteAddr }
func (r *requestWrapper) SetRemoteAddr(addr string) { r.r.RemoteAddr = addr }

type eRequestWrapper struct{ r *eHttp.Request }

func (r *eRequestWrapper) URL() *url.URL { return r.r.URL }
func (r *eRequestWrapper) TLS() *H.TlsInfo {
	if r.r.TLS == nil {
		return nil
	}
	return &H.TlsInfo{Version: r.r.TLS.Version, ServerName: r.r.TLS.ServerName, NegotiatedProtocol: r.r.TLS.NegotiatedProtocol}
}
func (r *eRequestWrapper) Body() io.ReadCloser       { return r.r.Body }
func (r *eRequestWrapper) Header() H.Header          { return r.r.Header }
func (r *eRequestWrapper) Method() string            { return r.r.Method }
func (r *eRequestWrapper) Context() context.Context  { return r.r.Context() }
func (r *eRequestWrapper) RequestURI() string        { return r.r.RequestURI }
func (r *eRequestWrapper) GetRemoteAddr() string     { return r.r.RemoteAddr }
func (r *eRequestWrapper) SetRemoteAddr(addr string) { r.r.RemoteAddr = addr }

// ResponseWriter wrappers
type responseWriterWrapper struct{ w http.ResponseWriter }

func (w *responseWriterWrapper) Header() H.Header            { return w.w.Header() }
func (w *responseWriterWrapper) Write(b []byte) (int, error) { return w.w.Write(b) }
func (w *responseWriterWrapper) WriteHeader(code int)        { w.w.WriteHeader(code) }

type eResponseWriterWrapper struct{ w eHttp.ResponseWriter }

func (w *eResponseWriterWrapper) Header() H.Header            { return w.w.Header() }
func (w *eResponseWriterWrapper) Write(b []byte) (int, error) { return w.w.Write(b) }
func (w *eResponseWriterWrapper) WriteHeader(code int)        { w.w.WriteHeader(code) }
