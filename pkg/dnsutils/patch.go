package dnsutils

import (
	"encoding/binary"
	"errors"

	"github.com/miekg/dns"
)

var (
	ErrInvalidDNSMsg = errors.New("invalid dns message")
)

// GetTTLOffsets returns the byte offsets of all TTL fields in a packed DNS message.
// It performs a minimal parse to avoid RR allocations.
func GetTTLOffsets(msg []byte) ([]uint16, error) {
	if len(msg) < 12 {
		return nil, ErrInvalidDNSMsg
	}

	// Header
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	nsCount := int(binary.BigEndian.Uint16(msg[8:10]))
	arCount := int(binary.BigEndian.Uint16(msg[10:12]))

	off := 12
	var err error

	// Skip Question Section
	for i := 0; i < qdCount; i++ {
		off, err = skipName(msg, off)
		if err != nil {
			return nil, err
		}
		off += 4 // Type(2) + Class(2)
	}

	totalRRs := anCount + nsCount + arCount
	if totalRRs == 0 {
		return nil, nil
	}

	offsets := make([]uint16, 0, totalRRs)

	// Answer, Authority, Additional Sections
	for i := 0; i < totalRRs; i++ {
		if off >= len(msg) {
			break
		}

		// Owner Name
		off, err = skipName(msg, off)
		if err != nil {
			return nil, err
		}

		if off+10 > len(msg) {
			return nil, ErrInvalidDNSMsg
		}

		rrType := binary.BigEndian.Uint16(msg[off : off+2])
		// TTL is at off + 4
		if rrType != dns.TypeOPT {
			offsets = append(offsets, uint16(off+4))
		}

		rdLen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10 + rdLen
	}

	return offsets, nil
}

func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, ErrInvalidDNSMsg
		}
		c := msg[off]
		if c == 0 {
			return off + 1, nil
		}
		if c&0xC0 == 0xC0 { // Pointer
			if off+2 > len(msg) {
				return 0, ErrInvalidDNSMsg
			}
			return off + 2, nil
		}
		if c&0xC0 != 0 { // Restricted label type (RFC 1682/1035)
			return 0, ErrInvalidDNSMsg
		}
		// Label length
		l := int(c)
		if l > 63 || off+1+l > len(msg) {
			return 0, ErrInvalidDNSMsg
		}
		off += l + 1
	}
}

// PatchTTLAndID patches the DNS ID and subtracts delta from all TTL fields at given offsets.
func PatchTTLAndID(msg []byte, id uint16, offsets []uint16, delta uint32) {
	// 1. Patch ID
	binary.BigEndian.PutUint16(msg[0:2], id)

	if delta == 0 {
		return
	}

	// 2. Patch TTLs
	for _, off := range offsets {
		if int(off)+4 > len(msg) {
			continue
		}
		curr := binary.BigEndian.Uint32(msg[off : off+4])
		if curr > delta {
			binary.BigEndian.PutUint32(msg[off:off+4], curr-delta)
		} else {
			binary.BigEndian.PutUint32(msg[off:off+4], 1) // Min 1s
		}
	}
}

// GetMinimalTTLFromRaw returns the minimal TTL value from the raw message using pre-calculated offsets.
func GetMinimalTTLFromRaw(msg []byte, offsets []uint16) uint32 {
	if len(offsets) == 0 {
		return 0
	}
	min := uint32(0xFFFFFFFF)
	for _, off := range offsets {
		if int(off)+4 > len(msg) {
			continue
		}
		ttl := binary.BigEndian.Uint32(msg[off : off+4])
		if ttl < min {
			min = ttl
		}
	}
	if min == 0xFFFFFFFF {
		return 0
	}
	return min
}

// HeaderInfo contains basic information from a DNS header.
type HeaderInfo struct {
	ID      uint16
	Rcode   int
	ANCount uint16
}

// GetHeaderInfo parses the DNS header without allocations.
func GetHeaderInfo(msg []byte) (HeaderInfo, error) {
	if len(msg) < 12 {
		return HeaderInfo{Rcode: -1}, ErrInvalidDNSMsg
	}
	return HeaderInfo{
		ID:      binary.BigEndian.Uint16(msg[0:2]),
		Rcode:   int(msg[3] & 0xF),
		ANCount: binary.BigEndian.Uint16(msg[6:8]),
	}, nil
}

// ShadowCopy returns a shallow copy of m. Only the header is copied.
// This is useful for modifying the ID or flags without affecting the original.
func ShadowCopy(m *dns.Msg) *dns.Msg {
	if m == nil {
		return nil
	}
	copy := *m
	return &copy
}
