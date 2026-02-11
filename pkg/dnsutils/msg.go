/*
 * Copyright (C) 2020-2026, IrineSistiana
 * Optimized by: bibica
 */

package dnsutils

import (
	"fmt"
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

// GetMsgKey tạo key định danh nhị phân (Không ID, không Salt).
// Tối ưu cho IPv6 và Domain dài với buffer 80 bytes.
func GetMsgKey(m *dns.Msg) string {
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

	return b.String()
}

func writeUint16(b *strings.Builder, v uint16) {
	b.WriteByte(byte(v >> 8))
	b.WriteByte(byte(v))
}

// --- Các hàm Helper phục vụ package khác (KHÔNG ĐƯỢC XÓA) ---

// QtypeToString chuyển đổi mã Type sang chuỗi (Phục vụ query_context)
func QtypeToString(qType uint16) string {
	if s, ok := dns.TypeToString[qType]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", qType)
}

// QclassToString chuyển đổi mã Class sang chuỗi (Phục vụ query_context)
func QclassToString(qClass uint16) string {
	if s, ok := dns.ClassToString[qClass]; ok {
		return s
	}
	return fmt.Sprintf("CLASS%d", qClass)
}

// FakeSOA tạo bản ghi SOA giả (Phục vụ pkg/hosts)
func FakeSOA(name string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "fake-ns.",
		Mbox:    "fake-mbox.",
		Serial:  0,
		Refresh: 28800,
		Retry:   7200,
		Expire:  604800,
		Minttl:  60,
	}
}

// --- Logic quản lý TTL cho Cache ---

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

func SubtractTTL(m *dns.Msg, delta uint32) (overflowed bool) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue
			}
			if hdr.Ttl > delta {
				hdr.Ttl -= delta
			} else {
				hdr.Ttl = 1
				overflowed = true
			}
		}
	}
	return
}
