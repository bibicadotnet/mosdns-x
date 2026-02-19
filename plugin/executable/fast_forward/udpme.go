package fastforward

import (
	"context"
	"net"
	"time"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"

	"github.com/miekg/dns"
)

type udpmeUpstream struct {
	addr string
}

func newUDPME(addr string) *udpmeUpstream {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	return &udpmeUpstream{addr: addr}
}

func (u *udpmeUpstream) Address() string {
	return u.addr
}

// Trusted now always returns true to satisfy the interface.
// The core racing logic in bundled_upstream no longer uses this value.
func (u *udpmeUpstream) Trusted() bool {
	return true
}

func (u *udpmeUpstream) ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, []byte, error) {
	ddl, ok := ctx.Deadline()
	if !ok {
		ddl = time.Now().Add(time.Second * 3)
	}

	if m.IsEdns0() != nil {
		return u.exchangeOPTM(m, ddl)
	}
	mc := m.Copy()
	mc.SetEdns0(512, false)
	r, raw, err := u.exchangeOPTM(mc, ddl)
	if err != nil {
		return nil, nil, err
	}
	dnsutils.RemoveEDNS0(r)
	return r, raw, nil
}

func (u *udpmeUpstream) exchangeOPTM(m *dns.Msg, ddl time.Time) (*dns.Msg, []byte, error) {
	c, err := dns.Dial("udp", u.addr)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()
	c.SetDeadline(ddl)
	if opt := m.IsEdns0(); opt != nil {
		c.UDPSize = opt.UDPSize()
	}

	if err := c.WriteMsg(m); err != nil {
		return nil, nil, err
	}

	for {
		// dns.Conn doesn't return raw bytes easily.
		// We could pack it ourselves, but for udpme it's fine to return nil raw for now.
		// Or we can use a custom read loop.
		// Since udpme is experimental, return nil raw.
		r, err := c.ReadMsg()
		if err != nil {
			return nil, nil, err
		}
		// UDPME logic: Only accept responses that contain EDNS0.
		// This is a mitigation against simple UDP spoofing.
		if r.IsEdns0() == nil {
			continue
		}
		return r, nil, nil
	}
}
