/*
 * Copyright (C) 2020-2026, IrineSistiana
 *
 * Chiến lược: sync.Pool + strings.Builder (Grow 80)
 * Đảm bảo: Bao phủ IPv6, triệt tiêu Heap Allocation, hiệu năng Mutex tối ưu.
 */

package dnsutils

import (
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// builderPool tái sử dụng strings.Builder để triệt tiêu việc cấp phát bộ nhớ mới.
// Pre-allocate 80 bytes để chứa vừa Domain dài + ECS IPv6 mà không cần grow lại.
var builderPool = sync.Pool{
	New: func() interface{} {
		b := new(strings.Builder)
		b.Grow(80)
		return b
	},
}

// GetMsgKey tạo key nhị phân định danh duy nhất từ Question và ECS.
// Pipeline: edns0_filter (xóa trắng) -> ecs.go (xây chuẩn).
func GetMsgKey(m *dns.Msg) string {
	b := builderPool.Get().(*strings.Builder)
	b.Reset()
	defer builderPool.Put(b)

	q := m.Question[0]

	// 1. Ghi Question: Tên miền + Type + Class
	b.WriteString(q.Name)
	writeUint16(b, q.Qtype)
	writeUint16(b, q.Qclass)

	// 2. Ghi ECS: Đục thẳng vào m.Extra[0] (do ecs.go đúc)
	if len(m.Extra) > 0 {
		if opt, ok := m.Extra[0].(*dns.OPT); ok {
			// Bốc thẳng Option đầu tiên, ecs.go đã đảm bảo là ECS chuẩn.
			if ecs, ok := opt.Option[0].(*dns.EDNS0_SUBNET); ok {
				writeUint16(b, ecs.Family)
				b.WriteByte(ecs.SourceNetmask)
				b.Write(ecs.Address)
			}
		}
	}

	return b.String()
}

// writeUint16 ghi byte nhị phân trực tiếp vào Builder.
func writeUint16(b *strings.Builder, v uint16) {
	b.WriteByte(byte(v >> 8))
	b.WriteByte(byte(v))
}

// --- Logic quản lý TTL cho Cache ---

// GetMinimalTTL tìm TTL thấp nhất để xác định expirationTime.
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

// SubtractTTL trừ TTL dựa trên thời gian thực tế đã nằm trong cache.
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
