package dnsutils

import (
	"encoding/binary"
)

// ExtractTTLOffsets parses DNS wire data once and returns the offsets of TTL fields.
func ExtractTTLOffsets(wire []byte) (offsets [8]uint16, count uint8) {
	if len(wire) < 12 {
		return
	}

	// Calculate total RRs to scan across all sections (Answer, Authority, Additional)
	totalRR := int(binary.BigEndian.Uint16(wire[6:8])) +
		int(binary.BigEndian.Uint16(wire[8:10])) +
		int(binary.BigEndian.Uint16(wire[10:12]))

	offset := 12
	qdcount := int(binary.BigEndian.Uint16(wire[4:6]))

	// 1. Skip Question Section
	for i := 0; i < qdcount && offset < len(wire); i++ {
		offset = skipName(wire, offset) + 4
	}

	// 2. Scan Resource Records
	for i := 0; i < totalRR && offset < len(wire); i++ {
		offset = skipName(wire, offset)

		// FAIL-SAFE: Check bounds after skipping name
		if offset+10 > len(wire) {
			break
		}

		rrtype := binary.BigEndian.Uint16(wire[offset : offset+2])

		// Skip OPT (41) to avoid patching EDNS0 metadata
		if rrtype != 41 && count < 8 {
			offsets[count] = uint16(offset + 4) // TTL is 4 bytes after Name
			count++
		}

		// Jump to next RR: TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) = 10 bytes
		rdLen := int(binary.BigEndian.Uint16(wire[offset+8 : offset+10]))
		offset += 10 + rdLen
	}
	return
}

func skipName(wire []byte, offset int) int {
	for offset < len(wire) {
		b := wire[offset]
		if b == 0 {
			return offset + 1
		}
		if b&0xC0 == 0xC0 {
			return offset + 2
		}
		offset += int(b) + 1
	}
	return offset
}
