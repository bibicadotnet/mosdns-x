package dnsutils

import (
	"strconv"

	"github.com/miekg/dns"
)

// GetMsgKey generates a compact binary identification key.
// Pre-condition: Detailed validations (e.g., Question count, normalization)
// are skipped here as they are strictly enforced by upstream pipeline plugins.
func GetMsgKey(m *dns.Msg, salt uint16) (string, error) {
	q := m.Question[0]
	size := len(q.Name) + 4 // Qname + Qtype(2) + Qclass(2)

	var ecs *dns.EDNS0_SUBNET
	// Pipeline architecture guarantees OPT is at Extra[0] and ECS is at Option[0].
	if len(m.Extra) > 0 {
		if opt, ok := m.Extra[0].(*dns.OPT); ok && len(opt.Option) > 0 {
			if e, ok := opt.Option[0].(*dns.EDNS0_SUBNET); ok {
				ecs = e
				size += 3 + len(ecs.Address) // Family(2) + Mask(1) + Address
			}
		}
	}

	// Optimized for performance: 2 small heap allocations (~20-64 bytes each).
	// One for the 'buf' slice and one for the 'string' copy.
	// This is cleaner and often faster than sync.Pool for small, short-lived keys.
	buf := make([]byte, 0, size)
	buf = append(buf, q.Name...)
	buf = append(buf, byte(q.Qtype>>8), byte(q.Qtype))
	buf = append(buf, byte(q.Qclass>>8), byte(q.Qclass))

	if ecs != nil {
		buf = append(buf, byte(ecs.Family>>8), byte(ecs.Family))
		buf = append(buf, ecs.SourceNetmask)
		buf = append(buf, ecs.Address...)
	}

	return string(buf), nil
}

// --- TTL Management ---

// GetMinimalTTL returns the smallest TTL in the message, skipping OPT records.
func GetMinimalTTL(m *dns.Msg) uint32 {
	minTTL := ^uint32(0)
	hasRecord := false
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype != dns.TypeOPT {
				hasRecord = true
				if hdr.Ttl < minTTL {
					minTTL = hdr.Ttl
				}
			}
		}
	}
	if !hasRecord {
		return 0
	}
	return minTTL
}

// applyTTL is a consolidated helper for Set/Max/Min TTL operations to reduce code duplication.
func applyTTL(m *dns.Msg, ttl uint32, mode int) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype != dns.TypeOPT {
				switch mode {
				case 1: // Maximum
					if hdr.Ttl > ttl {
						hdr.Ttl = ttl
					}
				case 2: // Minimal
					if hdr.Ttl < ttl {
						hdr.Ttl = ttl
					}
				default: // Set
					hdr.Ttl = ttl
				}
			}
		}
	}
}

func SetTTL(m *dns.Msg, ttl uint32)          { applyTTL(m, ttl, 0) }
func ApplyMaximumTTL(m *dns.Msg, ttl uint32) { applyTTL(m, ttl, 1) }
func ApplyMinimalTTL(m *dns.Msg, ttl uint32) { applyTTL(m, ttl, 2) }

// SubtractTTL reduces all RRs' TTL by delta. Returns overflowed=true if floor (1s) is hit.
func SubtractTTL(m *dns.Msg, delta uint32) (overflowed bool) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype != dns.TypeOPT {
				if hdr.Ttl > delta {
					hdr.Ttl -= delta
				} else {
					hdr.Ttl = 1
					overflowed = true
				}
			}
		}
	}
	return
}

// --- Helpers ---

func QclassToString(u uint16) string {
	return uint16Conv(u, dns.ClassToString)
}

func QtypeToString(u uint16) string {
	return uint16Conv(u, dns.TypeToString)
}

func uint16Conv(u uint16, m map[uint16]string) string {
	if s, ok := m[u]; ok {
		return s
	}
	return strconv.Itoa(int(u))
}

// GenEmptyReply creates a skeletal response with a fake SOA.
// Used for negative caching when an upstream error or block occurs.
func GenEmptyReply(q *dns.Msg, rcode int) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(q, rcode)
	r.RecursionAvailable = true

	name := "."
	if len(q.Question) > 0 {
		name = q.Question[0].Name
	}

	r.Ns = []dns.RR{FakeSOA(name)}
	return r
}

// FakeSOA returns a static SOA record.
func FakeSOA(name string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns:      "fake-ns.mosdns.fake.root.",
		Mbox:    "fake-mbox.mosdns.fake.root.",
		Serial:  2021110400,
		Refresh: 1800,
		Retry:   900,
		Expire:  604800,
		Minttl:  86400,
	}
}
