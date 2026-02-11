/*
 * Copyright (C) 2020-2026, IrineSistiana
 */

package dnsutils

import (
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// builderPool tái sử dụng vùng nhớ để triệt tiêu GC.
var builderPool = sync.Pool{
	New: func() interface{} {
		b := new(strings.Builder)
		b.Grow(128)
		return b
	},
}

// GetMsgKey tạo key nhị phân từ Question và ECS.
// Dựa trên Pipeline: edns0_filter xóa trắng -> ecs.go xây lại
// Key không chứa ID hay Salt vì nội dung đã được chuẩn hóa duy nhất.
func GetMsgKey(m *dns.Msg) string {
	b := builderPool.Get().(*strings.Builder)
	b.Reset()
	defer builderPool.Put(b)

	q := m.Question[0]

	// 1. Question: Định danh nội dung câu hỏi
	b.WriteString(q.Name)
	writeUint16(b, q.Qtype)
	writeUint16(b, q.Qclass)

	// 2. ECS: Đục thẳng vào bản ghi duy nhất trong Extra (do ecs.go đúc)
	if len(m.Extra) > 0 {
		if opt, ok := m.Extra[0].(*dns.OPT); ok {
			// Bốc thẳng Option đầu tiên, ecs.go đã đảm bảo nó là ECS sạch
			if ecs, ok := opt.Option[0].(*dns.EDNS0_SUBNET); ok {
				writeUint16(b, ecs.Family)
				b.WriteByte(ecs.SourceNetmask)
				b.Write(ecs.Address) 
			}
		}
	}

	return b.String()
}

// writeUint16 ghi byte nhị phân trực tiếp, CPU không tốn công parse chuỗi.
func writeUint16(b *strings.Builder, v uint16) {
	b.WriteByte(byte(v >> 8))
	b.WriteByte(byte(v))
}

// --- TTL Management (Phục vụ logic Cache Hit/Stale/Lazy) ---

// GetMinimalTTL lấy TTL nhỏ nhất để tính expirationTime cho MemCache.
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

// SetTTL cập nhật toàn bộ bản ghi (dùng cho Lazy Cache reply).
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

// SubtractTTL trừ TTL thực tế trước khi trả về từ Cache.
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
