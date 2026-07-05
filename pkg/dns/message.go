package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// DNS record types.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeOPT   uint16 = 41 // EDNS0 OPT pseudo-record (RFC 6891)
)

// defaultUDPSize is the EDNS0 UDP payload size we advertise. 1232 bytes is the
// widely-recommended value that avoids IP fragmentation on most paths.
const defaultUDPSize uint16 = 1232

// DNS classes.
const (
	ClassIN uint16 = 1
)

// DNS header flags.
const (
	FlagQR     uint16 = 1 << 15 // Query/Response
	FlagAA     uint16 = 1 << 10 // Authoritative Answer
	FlagTC     uint16 = 1 << 9  // Truncated
	FlagRD     uint16 = 1 << 8  // Recursion Desired
	FlagRA     uint16 = 1 << 7  // Recursion Available
	OpcodeMask uint16 = 0x7800
	RcodeMask  uint16 = 0x000F
)

// DNS response codes.
const (
	RcodeNoError  uint16 = 0
	RcodeFormat   uint16 = 1
	RcodeServFail uint16 = 2
	RcodeNXDomain uint16 = 3
	RcodeNotImpl  uint16 = 4
	RcodeRefused  uint16 = 5
)

// Header represents a DNS message header.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// IsResponse returns true if the QR bit is set.
func (h *Header) IsResponse() bool {
	return h.Flags&FlagQR != 0
}

// IsTruncated returns true if the TC bit is set.
func (h *Header) IsTruncated() bool {
	return h.Flags&FlagTC != 0
}

// Rcode returns the response code.
func (h *Header) Rcode() uint16 {
	return h.Flags & RcodeMask
}

// Question represents a DNS question section entry.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ResourceRecord represents a DNS resource record.
type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte

	// Parsed fields for convenience.
	ParsedData string
}

// Message represents a complete DNS message.
type Message struct {
	Header     Header
	Questions  []Question
	Answers    []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord

	// Raw keeps the original bytes for name decompression during parsing.
	Raw []byte
}

// TypeToString converts a DNS record type to its string representation.
func TypeToString(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeOPT:
		return "OPT"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// StringToType converts a string record type to its numeric value.
func StringToType(s string) (uint16, error) {
	switch strings.ToUpper(s) {
	case "A":
		return TypeA, nil
	case "NS":
		return TypeNS, nil
	case "CNAME":
		return TypeCNAME, nil
	case "MX":
		return TypeMX, nil
	case "TXT":
		return TypeTXT, nil
	case "AAAA":
		return TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown record type: %s", s)
	}
}

// NewQuery creates a new DNS query message. It includes an EDNS0 OPT
// pseudo-record in the additional section advertising a larger UDP payload
// size (defaultUDPSize), so servers may return larger UDP responses instead of
// truncating and forcing a TCP round-trip (RFC 6891).
func NewQuery(id uint16, name string, qtype uint16) *Message {
	return &Message{
		Header: Header{
			ID:      id,
			Flags:   0, // Standard query, no recursion desired (we do it ourselves)
			QDCount: 1,
			ARCount: 1,
		},
		Questions: []Question{
			{
				Name:  name,
				Type:  qtype,
				Class: ClassIN,
			},
		},
		Additional: []ResourceRecord{newOPTRecord(defaultUDPSize)},
	}
}

// newOPTRecord builds an EDNS0 OPT pseudo-record. Per RFC 6891 the OPT record
// has an empty root name, TYPE=41, and the CLASS field carries the requestor's
// UDP payload size. TTL carries extended rcode/flags (0 here) and there is no
// rdata.
func newOPTRecord(udpSize uint16) ResourceRecord {
	return ResourceRecord{
		Name:  "",
		Type:  TypeOPT,
		Class: udpSize,
		TTL:   0,
		RData: nil,
	}
}

// Serialize converts a DNS message to wire format bytes.
func (m *Message) Serialize() ([]byte, error) {
	buf := make([]byte, 12) // Header is 12 bytes

	binary.BigEndian.PutUint16(buf[0:2], m.Header.ID)
	binary.BigEndian.PutUint16(buf[2:4], m.Header.Flags)
	binary.BigEndian.PutUint16(buf[4:6], m.Header.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], m.Header.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], m.Header.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], m.Header.ARCount)

	for _, q := range m.Questions {
		nameBytes := encodeName(q.Name)
		buf = append(buf, nameBytes...)
		b := make([]byte, 4)
		binary.BigEndian.PutUint16(b[0:2], q.Type)
		binary.BigEndian.PutUint16(b[2:4], q.Class)
		buf = append(buf, b...)
	}

	// Emit additional-section records (e.g. the EDNS0 OPT pseudo-record).
	for _, rr := range m.Additional {
		buf = append(buf, encodeName(rr.Name)...)
		meta := make([]byte, 10)
		binary.BigEndian.PutUint16(meta[0:2], rr.Type)
		binary.BigEndian.PutUint16(meta[2:4], rr.Class)
		binary.BigEndian.PutUint32(meta[4:8], rr.TTL)
		binary.BigEndian.PutUint16(meta[8:10], uint16(len(rr.RData)))
		buf = append(buf, meta...)
		buf = append(buf, rr.RData...)
	}

	return buf, nil
}

// encodeName encodes a domain name in DNS wire format.
func encodeName(name string) []byte {
	var buf []byte

	if name == "" || name == "." {
		return []byte{0}
	}

	name = strings.TrimSuffix(name, ".")

	parts := strings.Split(name, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0)
	return buf
}

// Parse parses a raw DNS message from bytes.
func Parse(data []byte) (*Message, error) {
	if len(data) < 12 {
		return nil, errors.New("dns message too short")
	}

	msg := &Message{
		Raw: data,
	}

	msg.Header = Header{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}

	offset := 12

	// Parse questions.
	for i := 0; i < int(msg.Header.QDCount); i++ {
		name, newOffset, err := decodeName(data, offset)
		if err != nil {
			return nil, fmt.Errorf("parsing question name: %w", err)
		}
		offset = newOffset

		if offset+4 > len(data) {
			return nil, errors.New("question section too short")
		}

		q := Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		}
		offset += 4
		msg.Questions = append(msg.Questions, q)
	}

	// Parse answer records.
	var err error
	msg.Answers, offset, err = parseResourceRecords(data, offset, int(msg.Header.ANCount))
	if err != nil {
		return nil, fmt.Errorf("parsing answer section: %w", err)
	}

	// Parse authority records.
	msg.Authority, offset, err = parseResourceRecords(data, offset, int(msg.Header.NSCount))
	if err != nil {
		return nil, fmt.Errorf("parsing authority section: %w", err)
	}

	// Parse additional records.
	msg.Additional, _, err = parseResourceRecords(data, offset, int(msg.Header.ARCount))
	if err != nil {
		return nil, fmt.Errorf("parsing additional section: %w", err)
	}

	return msg, nil
}

// parseResourceRecords parses count resource records starting at offset.
func parseResourceRecords(data []byte, offset, count int) ([]ResourceRecord, int, error) {
	var records []ResourceRecord

	for i := 0; i < count; i++ {
		name, newOffset, err := decodeName(data, offset)
		if err != nil {
			return nil, 0, fmt.Errorf("parsing RR name: %w", err)
		}
		offset = newOffset

		if offset+10 > len(data) {
			return nil, 0, errors.New("resource record too short")
		}

		rr := ResourceRecord{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
			TTL:   binary.BigEndian.Uint32(data[offset+4 : offset+8]),
		}
		rdLength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLength) > len(data) {
			return nil, 0, errors.New("rdata extends beyond message")
		}

		rr.RData = make([]byte, rdLength)
		copy(rr.RData, data[offset:offset+int(rdLength)])

		// Parse rdata based on type.
		rr.ParsedData = parseRData(rr.Type, data, offset, int(rdLength))

		offset += int(rdLength)
		records = append(records, rr)
	}

	return records, offset, nil
}

// parseRData interprets rdata based on record type.
func parseRData(rrType uint16, data []byte, offset, length int) string {
	switch rrType {
	case TypeA:
		if length == 4 {
			return net.IP(data[offset : offset+4]).String()
		}
	case TypeAAAA:
		if length == 16 {
			return net.IP(data[offset : offset+16]).String()
		}
	case TypeCNAME, TypeNS:
		name, _, err := decodeName(data, offset)
		if err == nil {
			return name
		}
	case TypeMX:
		if length >= 3 {
			pref := binary.BigEndian.Uint16(data[offset : offset+2])
			name, _, err := decodeName(data, offset+2)
			if err == nil {
				return fmt.Sprintf("%d %s", pref, name)
			}
		}
	case TypeTXT:
		return parseTXT(data[offset : offset+length])
	}
	return fmt.Sprintf("<rdata %d bytes>", length)
}

// parseTXT parses TXT record data, which consists of one or more length-prefixed strings.
func parseTXT(data []byte) string {
	var parts []string
	i := 0
	for i < len(data) {
		strLen := int(data[i])
		i++
		if i+strLen > len(data) {
			break
		}
		parts = append(parts, string(data[i:i+strLen]))
		i += strLen
	}
	return strings.Join(parts, "")
}

// decodeName decodes a DNS name with pointer compression support.
func decodeName(data []byte, offset int) (string, int, error) {
	var parts []string
	visited := make(map[int]bool)
	jumped := false
	returnOffset := 0

	for {
		if offset >= len(data) {
			return "", 0, errors.New("name offset out of bounds")
		}

		if visited[offset] {
			return "", 0, errors.New("compression loop detected")
		}
		visited[offset] = true

		length := int(data[offset])

		// Check for pointer.
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, errors.New("pointer offset out of bounds")
			}
			if !jumped {
				returnOffset = offset + 2
			}
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2])) & 0x3FFF
			offset = pointer
			jumped = true
			continue
		}

		offset++

		if length == 0 {
			break
		}

		if offset+length > len(data) {
			return "", 0, errors.New("label extends beyond message")
		}

		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}

	if !jumped {
		returnOffset = offset
	}

	return strings.Join(parts, "."), returnOffset, nil
}
