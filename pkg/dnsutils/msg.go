/*
 * Copyright (C) 2020-2026, IrineSistiana
 *
 * This file is part of mosdns.
 * Optimized for real-world production performance.
 */

package dnsutils

import (
	"encoding/binary"
	"strconv"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/pool"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

// GetMinimalTTL returns the minimal TTL of this DNS message.
// If the message has no records, it returns 0.
func GetMinimalTTL(m *dns.Msg) uint32 {
	minTTL := ^uint32(0)
	hasRecord := false
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue // OPT record TTL is not a real TTL.
			}
			hasRecord = true
			ttl := hdr.Ttl
			if ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	if !hasRecord {
		return 0
	}
	return minTTL
}

// SetTTL updates the TTL of all records in the message to the specified value, excluding OPT records.
func SetTTL(m *dns.Msg, ttl uint32) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue
			}
			hdr.Ttl = ttl
		}
	}
}

func ApplyMaximumTTL(m *dns.Msg, ttl uint32) {
	applyTTL(m, ttl, true)
}

func ApplyMinimalTTL(m *dns.Msg, ttl uint32) {
	applyTTL(m, ttl, false)
}

// SubtractTTL subtracts delta from every record's TTL.
// Returns overflowed = true if any TTL becomes smaller than delta.
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

func uint16Conv(u uint16, m map[uint16]string) string {
	if s, ok := m[u]; ok {
		return s
	}
	return strconv.Itoa(int(u))
}

func QclassToString(u uint16) string {
	return uint16Conv(u, dns.ClassToString)
}

func QtypeToString(u uint16) string {
	return uint16Conv(u, dns.TypeToString)
}

// GenEmptyReply generates an empty DNS reply with the specified Rcode.
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

// FakeSOA returns a dummy SOA record for empty replies.
func FakeSOA(name string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:    name,
			Rrtype:  dns.TypeSOA,
			Class:   dns.ClassINET,
			Ttl:     300,
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

// GetMsgKey unpacks m and set its id to salt.
// This is the most efficient method for long-lived cache keys: 1 allocation, zero-copy string.
func GetMsgKey(m *dns.Msg, salt uint16) (string, error) {
	wireMsg, err := m.Pack()
	if err != nil {
		return "", err
	}
	// In-place modification of the ID field with the provided salt
	wireMsg[0] = byte(salt >> 8)
	wireMsg[1] = byte(salt)

	// Safe zero-copy because wireMsg is unique to this caller and won't be reused.
	return utils.BytesToStringUnsafe(wireMsg), nil
}

// GetMsgKeyWithBytesSalt appends a byte slice salt to the packed message key.
// Uses direct make() and copy() for better performance and predictable GC behavior.
func GetMsgKeyWithBytesSalt(m *dns.Msg, salt []byte) (string, error) {
	wireMsg, buf, err := pool.PackBuffer(m)
	if err != nil {
		return "", err
	}
	defer buf.Release()

	// Mask ID to 0 for consistent key generation
	wireMsg[0] = 0
	wireMsg[1] = 0

	// Combine into a single allocation
	result := make([]byte, len(wireMsg)+len(salt))
	copy(result, wireMsg)
	copy(result[len(wireMsg):], salt)

	// string() is required here as pooled buffer is released.
	return string(result), nil
}

// GetMsgKeyWithInt64Salt appends an int64 salt using stack allocation for the salt buffer.
func GetMsgKeyWithInt64Salt(m *dns.Msg, salt int64) (string, error) {
	var b [8]byte // Stack allocated to prevent heap escape
	binary.BigEndian.PutUint64(b[:], uint64(salt))
	return GetMsgKeyWithBytesSalt(m, b[:])
}
