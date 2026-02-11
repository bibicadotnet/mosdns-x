package dnsutils

import (
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// builderPool tái sử dụng strings.Builder (Grow 80) để triệt tiêu Heap Allocation.
var builderPool = sync.Pool{
	New: func() interface{} {
		b := new(strings.Builder)
		b.Grow(80)
		return b
	},
}

// GetMsgKey tạo key định danh nhị phân (Không dùng ID/Salt để tối ưu Cache).
// Nhận salt uint16 để giữ tương thích với plugin cache hiện tại nhưng không băm vào key.
func GetMsgKey(m *dns.Msg, salt uint16) (string, error) {
	b := builderPool.Get().(*strings.Builder)
	b.Reset()
	defer builderPool.Put(b)

	q := m.Question[0]

	// 1. Question
	b.WriteString(q.Name)
	writeUint16(b, q.Qtype)
	writeUint16(b, q.Qclass)

	// 2. ECS (Đục thẳng Extra[0])
	if len(m.Extra) > 0 {
		if opt, ok := m.Extra[0].(*dns.OPT); ok {
			if ecs, ok := opt.Option[0].(*dns.EDNS0_SUBNET); ok {
				writeUint16(b, ecs.Family)
				b.WriteByte(ecs.SourceNetmask)
				b.Write(ecs.Address)
			}
		}
	}

	return b.String(), nil
}

func writeUint16(b *strings.Builder, v uint16) {
	b.WriteByte(byte(v >> 8))
	b.WriteByte(byte(v))
}

// --- Các hàm Helper phục vụ package khác ---

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

func GenEmptyReply(q *dns.Msg, rcode int) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(q, rcode)
	r.RecursionAvailable = true

	var name string
	if len(q.Question) > 0 {
		name = q.Question[0].Name
	} else {
		name = "."
	}

	r.Ns = []dns.RR{FakeSOA(name)}
	return r
}

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

// --- Logic quản lý TTL ---

func GetMinimalTTL(m *dns.Msg) uint32 {
	minTTL := ^uint32(0)
	hasRecord := false
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue
			}
			hasRecord = true
			if hdr.Ttl < minTTL {
				minTTL = hdr.Ttl
			}
		}
	}
	if !hasRecord {
		return 0
	}
	return minTTL
}

func SetTTL(m *dns.Msg, ttl uint32) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype != dns.TypeOPT {
				hdr.Ttl = ttl
			}
		}
	}
}

func ApplyMaximumTTL(m *dns.Msg, ttl uint32) {
	applyTTL(m, ttl, true)
}

func ApplyMinimalTTL(m *dns.Msg, ttl uint32) {
	applyTTL(m, ttl, false)
}

func applyTTL(m *dns.Msg, ttl uint32, maximum bool) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue
			}
			if maximum {
				if hdr.Ttl > ttl {
					hdr.Ttl = ttl
				}
			} else {
				if hdr.Ttl < ttl {
					hdr.Ttl = ttl
				}
			}
		}
	}
}

func SubtractTTL(m *dns.Msg, delta uint32) (overflowed bool) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue
			}
			if ttl := hdr.Ttl; ttl > delta {
				hdr.Ttl = ttl - delta
			} else {
				hdr.Ttl = 1
				overflowed = true
			}
		}
	}
	return
}
