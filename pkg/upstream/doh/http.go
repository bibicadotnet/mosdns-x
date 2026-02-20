package doh

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/miekg/dns"
	"gitlab.com/go-extension/http"

	C "github.com/pmkol/mosdns-x/constant"
	"github.com/pmkol/mosdns-x/pkg/pool"
)

const dnsContentType = "application/dns-message"

var (
	bufPool          = pool.NewBytesBufPool(65535)
	defaultUserAgent = fmt.Sprintf("mosdns-x/%s", C.Version)
)

type Upstream struct {
	url       *url.URL
	transport *http.Transport
}

func NewUpstream(url *url.URL, transport *http.Transport) *Upstream {
	return &Upstream{url, transport}
}

func (u *Upstream) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	q.Id = 0

	wire, buf, err := pool.PackBuffer(q)
	if err != nil {
		return nil, err
	}
	defer buf.Release()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url.String(), bytes.NewReader(wire))
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
		return nil, fmt.Errorf("http %d", res.StatusCode)
	}

	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, dnsContentType) {
		return nil, fmt.Errorf("invalid content-type: %s", ct)
	}

	bb := bufPool.Get()
	defer bufPool.Release(bb)

	if _, err = bb.ReadFrom(res.Body); err != nil {
		return nil, err
	}

	if bb.Len() == 0 {
		return nil, fmt.Errorf("empty response")
	}

	r := new(dns.Msg)
	if err := r.Unpack(bb.Bytes()); err != nil {
		return nil, err
	}
	return r, nil
}

func (u *Upstream) Close() error {
	u.transport.CloseIdleConnections()
	return nil
}
