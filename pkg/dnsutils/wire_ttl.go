package dnsutils

import (
	"encoding/binary"
)

// ExtractTTLOffsets parses DNS wire data to find TTL field positions.
// Optimized for: Answer + Authority sections. Skips Additional (arcount).
func ExtractTTLOffsets(wire []byte) (offsets [8]uint16, count uint8) {
	// Header(12) + Min Question(4) = 16 bytes
	if len(wire) < 16 {
		return
	}

	// 1. Calculate total RRs to scan (Answer + Authority).
	// We skip Additional (arcount at bytes 10-11) as pipeline ensures no OPT records.
	totalRR := int(binary.BigEndian.Uint16(wire[6:8])) + // ANCOUNT
		int(binary.BigEndian.Uint16(wire[8:10]))        // NSCOUNT (Critical for NXDOMAIN/SOA)

	if totalRR <= 0 {
		return
	}

	// Cap to 8 records as per your optimized design
	if totalRR > 8 {
		totalRR = 8
	}

	// 2. Skip Question Section
	// Standard queries have 1 question (qdcount at bytes 4-5)
	qdcount := int(binary.BigEndian.Uint16(wire[4:6]))
	offset := 12
	for i := 0; i < qdcount && offset < len(wire); i++ {
		offset = skipName(wire, offset) + 4 // Skip Name + Type(2) + Class(2)
	}

	// 3. Scan Resource Records (Answer & Authority)
	// This covers both IP responses (A/AAAA) and NXDOMAIN (SOA in Authority)
	for i := 0; i < totalRR && offset < len(wire); i++ {
		offset = skipName(wire, offset)

		// Bound check: TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) = 10 bytes
		if offset+10 > len(wire) {
			break
		}

		// TTL is located 4 bytes after the end of the Name (after Type and Class)
		// No OPT (41) check needed because arcount is ignored/stripped.
		offsets[count] = uint16(offset + 4)
		count++

		// Jump to next RR: Fixed header(10) + RData length
		rdLen := int(binary.BigEndian.Uint16(wire[offset+8 : offset+10]))
		offset += 10 + rdLen
	}
	return
}

// skipName efficiently jumps over DNS names (including compression pointers)
func skipName(wire []byte, offset int) int {
	for offset < len(wire) {
		b := wire[offset]
		if b == 0 {
			return offset + 1
		}
		if b&0xC0 == 0xC0 { // Compression pointer: 2 bytes
			return offset + 2
		}
		// Follow label length
		offset += int(b) + 1
	}
	return offset
}
