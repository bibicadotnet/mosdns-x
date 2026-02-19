/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 */

package doh

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/miekg/dns"
	C "github.com/pmkol/mosdns-x/constant"
	"github.com/pmkol/mosdns-x/pkg/pool"
	"gitlab.com/go-extension/http"
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

func (u *Upstream) ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, []byte, error) {
	r, err := u.Exchange(ctx, m)
	return r, nil, err
}

func (u *Upstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	m.Id = 0
	wire, buf, err := pool.PackBuffer(m)
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

	if res.StatusCode != 200 {
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

	data := make([]byte, bb.Len())
	copy(data, bb.Bytes())

	r := new(dns.Msg)
	if err := r.Unpack(data); err != nil {
		return nil, err
	}
	return r, nil
}

func (u *Upstream) Close() error {
	u.transport.CloseIdleConnections()
	return nil
}
