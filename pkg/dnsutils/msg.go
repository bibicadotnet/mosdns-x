package dnsutils

import (
	"strconv"

	"github.com/cespare/xxhash/v2"
	"github.com/miekg/dns"
)

// GetMsgHash generates an 8-byte hash key for the message.
// Pre-condition: Detailed validations (e.g., Question count, normalization)
// are skipped here as they are strictly enforced by upstream pipeline plugins.
func GetMsgHash(m *dns.Msg, salt uint16) uint64 {
	q := m.Question[0]

	var buf [512]byte
	b := buf[:0]

	b = append(b, q.Name...)
	b = append(b, byte(q.Qtype>>8), byte(q.Qtype))
	b = append(b, byte(q.Qclass>>8), byte(q.Qclass))
	b = append(b, byte(salt>>8), byte(salt))

	if len(m.Extra) > 0 {
		if opt, ok := m.Extra[0].(*dns.OPT); ok && len(opt.Option) > 0 {
			if ecs, ok := opt.Option[0].(*dns.EDNS0_SUBNET); ok {
				b = append(b, byte(ecs.Family>>8), byte(ecs.Family))
				b = append(b, ecs.SourceNetmask)
				b = append(b, ecs.Address...)
			}
		}
	}

	return xxhash.Sum64(b)
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
