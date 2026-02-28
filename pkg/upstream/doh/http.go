package doh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/miekg/dns"
	"gitlab.com/go-extension/http"

	C "github.com/pmkol/mosdns-x/constant"
	"github.com/pmkol/mosdns-x/pkg/pool"
)

const dnsContentType = "application/dns-message"

var defaultUserAgent = fmt.Sprintf("mosdns-x/%s", C.Version)

type Upstream struct {
	urlStr    string
	transport *http.Transport
}

func NewUpstream(url *url.URL, transport *http.Transport) *Upstream {
	return &Upstream{
		urlStr:    url.String(),
		transport: transport,
	}
}

func (u *Upstream) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
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
		return nil, fmt.Errorf("http %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, dnsContentType) {
		return nil, fmt.Errorf("invalid content-type: %s", ct)
	}

	// Use 4KB buffer from pool (matches DNS workload optimization in allocator).
	// DNS responses are typically 50-4096 bytes, well within this shard.
	bb := pool.GetBuf(4096)
	defer bb.Release()

	// Read response into pooled buffer
	buf2 := bb.AllBytes()
	var total int
	for total < len(buf2) {
		n, err := res.Body.Read(buf2[total:])
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	// Check for overflow - if buffer is full, ensure no more data exists
	if total == 4096 {
		oneByte := make([]byte, 1)
		n, _ := res.Body.Read(oneByte)
		if n > 0 {
			return nil, fmt.Errorf("response exceeds maximum size of 4096 bytes")
		}
	}

	if total == 0 {
		return nil, fmt.Errorf("empty response")
	}

	r := new(dns.Msg)
	if err := r.Unpack(buf2[:total]); err != nil {
		return nil, err
	}
	return r, nil
}

func (u *Upstream) Close() error {
	u.transport.CloseIdleConnections()
	return nil
}
