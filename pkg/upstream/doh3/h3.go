package doh3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"

	C "github.com/pmkol/mosdns-x/constant"
	"github.com/pmkol/mosdns-x/pkg/pool"
)

const dnsContentType = "application/dns-message"

var defaultUserAgent = fmt.Sprintf("mosdns-x/%s", C.Version)

type Upstream struct {
	urlStr    string
	transport *http3.Transport
}

func NewUpstream(url *url.URL, transport *http3.Transport) *Upstream {
	return &Upstream{
		urlStr:    url.String(),
		transport: transport,
	}
}

func (u *Upstream) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	q.Id = 0
	wire, buf, err := pool.PackBuffer(q)
	if err != nil {
		return nil, err
	}
	defer buf.Release()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.urlStr, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dnsContentType)
	req.Header.Set("Accept", dnsContentType)
	req.Header.Set("User-Agent", defaultUserAgent)

	res, err := u.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status %v: %s", res.StatusCode, res.Status)
	}
	if contentType := res.Header.Get("Content-Type"); contentType != dnsContentType {
		return nil, fmt.Errorf("unexpected content type: %s", contentType)
	}
	if contentLength := res.Header.Get("Content-Length"); contentLength != "" {
		if length, err := strconv.Atoi(contentLength); err == nil && length == 0 {
			return nil, fmt.Errorf("empty response")
		}
	}

	respBytes, err := io.ReadAll(io.LimitReader(res.Body, 4097))
	if err != nil {
		return nil, err
	}
	if len(respBytes) > 4096 {
		return nil, fmt.Errorf("response too large: %d bytes", len(respBytes))
	}
	if len(respBytes) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	r := new(dns.Msg)
	if err := r.Unpack(respBytes); err != nil {
		return nil, err
	}
	return r, nil
}

func (u *Upstream) Close() error {
	u.transport.CloseIdleConnections()
	return u.transport.Close()
}
