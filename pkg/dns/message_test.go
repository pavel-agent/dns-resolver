package dns

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestTypeToString(t *testing.T) {
	tests := []struct {
		input uint16
		want  string
	}{
		{TypeA, "A"},
		{TypeNS, "NS"},
		{TypeCNAME, "CNAME"},
		{TypeMX, "MX"},
		{TypeTXT, "TXT"},
		{TypeAAAA, "AAAA"},
		{99, "TYPE99"},
		{0, "TYPE0"},
	}

	for _, tt := range tests {
		got := TypeToString(tt.input)
		if got != tt.want {
			t.Errorf("TypeToString(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestStringToType(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{"A", TypeA, false},
		{"a", TypeA, false},
		{"NS", TypeNS, false},
		{"ns", TypeNS, false},
		{"CNAME", TypeCNAME, false},
		{"cname", TypeCNAME, false},
		{"MX", TypeMX, false},
		{"TXT", TypeTXT, false},
		{"AAAA", TypeAAAA, false},
		{"aaaa", TypeAAAA, false},
		{"INVALID", 0, true},
		{"", 0, true},
		{"PTR", 0, true},
	}

	for _, tt := range tests {
		got, err := StringToType(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("StringToType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("StringToType(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestHeaderIsResponse(t *testing.T) {
	h := &Header{Flags: FlagQR}
	if !h.IsResponse() {
		t.Error("expected IsResponse to return true when QR flag is set")
	}

	h = &Header{Flags: 0}
	if h.IsResponse() {
		t.Error("expected IsResponse to return false when QR flag is not set")
	}
}

func TestHeaderIsTruncated(t *testing.T) {
	h := &Header{Flags: FlagTC}
	if !h.IsTruncated() {
		t.Error("expected IsTruncated to return true when TC flag is set")
	}

	h = &Header{Flags: 0}
	if h.IsTruncated() {
		t.Error("expected IsTruncated to return false when TC flag is not set")
	}
}

func TestHeaderRcode(t *testing.T) {
	tests := []struct {
		flags uint16
		want  uint16
	}{
		{0x0000, RcodeNoError},
		{0x0001, RcodeFormat},
		{0x0002, RcodeServFail},
		{0x0003, RcodeNXDomain},
		{0x0004, RcodeNotImpl},
		{0x0005, RcodeRefused},
		{FlagQR | RcodeNXDomain, RcodeNXDomain},
	}

	for _, tt := range tests {
		h := &Header{Flags: tt.flags}
		if got := h.Rcode(); got != tt.want {
			t.Errorf("Header{Flags: 0x%04x}.Rcode() = %d, want %d", tt.flags, got, tt.want)
		}
	}
}

func TestNewQuery(t *testing.T) {
	msg := NewQuery(0x1234, "example.com", TypeA)

	if msg.Header.ID != 0x1234 {
		t.Errorf("ID = 0x%04x, want 0x1234", msg.Header.ID)
	}
	if msg.Header.Flags != 0 {
		t.Errorf("Flags = 0x%04x, want 0", msg.Header.Flags)
	}
	if msg.Header.QDCount != 1 {
		t.Errorf("QDCount = %d, want 1", msg.Header.QDCount)
	}
	if msg.Header.ANCount != 0 {
		t.Errorf("ANCount = %d, want 0", msg.Header.ANCount)
	}
	if len(msg.Questions) != 1 {
		t.Fatalf("len(Questions) = %d, want 1", len(msg.Questions))
	}
	if msg.Questions[0].Name != "example.com" {
		t.Errorf("Question Name = %q, want %q", msg.Questions[0].Name, "example.com")
	}
	if msg.Questions[0].Type != TypeA {
		t.Errorf("Question Type = %d, want %d", msg.Questions[0].Type, TypeA)
	}
	if msg.Questions[0].Class != ClassIN {
		t.Errorf("Question Class = %d, want %d", msg.Questions[0].Class, ClassIN)
	}
}

func TestEncodeName(t *testing.T) {
	tests := []struct {
		name string
		want []byte
	}{
		{"", []byte{0}},
		{".", []byte{0}},
		{"example.com", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"example.com.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"a.b.c", []byte{1, 'a', 1, 'b', 1, 'c', 0}},
	}

	for _, tt := range tests {
		got := encodeName(tt.name)
		if len(got) != len(tt.want) {
			t.Errorf("encodeName(%q) length = %d, want %d", tt.name, len(got), len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("encodeName(%q)[%d] = 0x%02x, want 0x%02x", tt.name, i, got[i], tt.want[i])
				break
			}
		}
	}
}

func TestSerializeAndParse(t *testing.T) {
	original := NewQuery(0xABCD, "example.com", TypeA)
	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed.Header.ID != original.Header.ID {
		t.Errorf("parsed ID = 0x%04x, want 0x%04x", parsed.Header.ID, original.Header.ID)
	}
	if parsed.Header.QDCount != 1 {
		t.Errorf("parsed QDCount = %d, want 1", parsed.Header.QDCount)
	}
	if len(parsed.Questions) != 1 {
		t.Fatalf("parsed questions count = %d, want 1", len(parsed.Questions))
	}
	if parsed.Questions[0].Name != "example.com" {
		t.Errorf("parsed question name = %q, want %q", parsed.Questions[0].Name, "example.com")
	}
	if parsed.Questions[0].Type != TypeA {
		t.Errorf("parsed question type = %d, want %d", parsed.Questions[0].Type, TypeA)
	}
	if parsed.Questions[0].Class != ClassIN {
		t.Errorf("parsed question class = %d, want %d", parsed.Questions[0].Class, ClassIN)
	}
}

func TestSerializeMultipleQuestionTypes(t *testing.T) {
	types := []uint16{TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeNS, TypeTXT}

	for _, qtype := range types {
		msg := NewQuery(1, "test.example.com", qtype)
		data, err := msg.Serialize()
		if err != nil {
			t.Fatalf("Serialize failed for type %s: %v", TypeToString(qtype), err)
		}

		parsed, err := Parse(data)
		if err != nil {
			t.Fatalf("Parse failed for type %s: %v", TypeToString(qtype), err)
		}

		if parsed.Questions[0].Type != qtype {
			t.Errorf("roundtrip type = %d, want %d", parsed.Questions[0].Type, qtype)
		}
	}
}

func TestNewQueryIncludesOPTRecord(t *testing.T) {
	msg := NewQuery(0x1234, "example.com", TypeA)

	if msg.Header.ARCount != 1 {
		t.Fatalf("ARCount = %d, want 1 (EDNS0 OPT record)", msg.Header.ARCount)
	}
	if len(msg.Additional) != 1 {
		t.Fatalf("len(Additional) = %d, want 1", len(msg.Additional))
	}
	opt := msg.Additional[0]
	if opt.Type != TypeOPT {
		t.Errorf("OPT Type = %d, want %d", opt.Type, TypeOPT)
	}
	if opt.Class != defaultUDPSize {
		t.Errorf("OPT advertised UDP size = %d, want %d", opt.Class, defaultUDPSize)
	}
}

func TestSerializeQueryContainsOPT(t *testing.T) {
	msg := NewQuery(0xABCD, "example.com", TypeA)
	data, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if parsed.Header.ARCount != 1 {
		t.Fatalf("parsed ARCount = %d, want 1", parsed.Header.ARCount)
	}
	if len(parsed.Additional) != 1 {
		t.Fatalf("parsed Additional count = %d, want 1", len(parsed.Additional))
	}
	opt := parsed.Additional[0]
	if opt.Type != TypeOPT {
		t.Errorf("parsed OPT Type = %d, want %d", opt.Type, TypeOPT)
	}
	if opt.Class != defaultUDPSize {
		t.Errorf("parsed OPT advertised UDP size = %d, want %d", opt.Class, defaultUDPSize)
	}
	if opt.Name != "" {
		t.Errorf("OPT name = %q, want root (empty)", opt.Name)
	}
}

func TestParseTooShort(t *testing.T) {
	_, err := Parse([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error parsing too-short message")
	}
}

func TestParseEmptyMessage(t *testing.T) {
	// A valid 12-byte header with zero counts.
	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data[0:2], 0x1234)

	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if msg.Header.ID != 0x1234 {
		t.Errorf("ID = 0x%04x, want 0x1234", msg.Header.ID)
	}
	if len(msg.Questions) != 0 {
		t.Errorf("expected no questions, got %d", len(msg.Questions))
	}
}

// buildDNSResponse constructs a minimal DNS response with an A record answer.
func buildDNSResponse(id uint16, name string, ip net.IP) []byte {
	var buf []byte

	// Header: 12 bytes
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], FlagQR) // QR=1, response
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCount
	binary.BigEndian.PutUint16(header[6:8], 1)      // ANCount
	binary.BigEndian.PutUint16(header[8:10], 0)     // NSCount
	binary.BigEndian.PutUint16(header[10:12], 0)    // ARCount
	buf = append(buf, header...)

	// Question section
	nameBytes := encodeName(name)
	buf = append(buf, nameBytes...)
	qFooter := make([]byte, 4)
	binary.BigEndian.PutUint16(qFooter[0:2], TypeA)
	binary.BigEndian.PutUint16(qFooter[2:4], ClassIN)
	buf = append(buf, qFooter...)

	// Answer section (A record)
	buf = append(buf, encodeName(name)...)
	rrMeta := make([]byte, 10)
	binary.BigEndian.PutUint16(rrMeta[0:2], TypeA)
	binary.BigEndian.PutUint16(rrMeta[2:4], ClassIN)
	binary.BigEndian.PutUint32(rrMeta[4:8], 300) // TTL
	binary.BigEndian.PutUint16(rrMeta[8:10], 4)  // RDLength
	buf = append(buf, rrMeta...)
	buf = append(buf, ip.To4()...)

	return buf
}

func TestParseResponseWithARecord(t *testing.T) {
	ip := net.IPv4(93, 184, 216, 34)
	data := buildDNSResponse(0x1234, "example.com", ip)

	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if !msg.Header.IsResponse() {
		t.Error("expected response flag to be set")
	}
	if msg.Header.QDCount != 1 {
		t.Errorf("QDCount = %d, want 1", msg.Header.QDCount)
	}
	if msg.Header.ANCount != 1 {
		t.Errorf("ANCount = %d, want 1", msg.Header.ANCount)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
	}

	ans := msg.Answers[0]
	if ans.Name != "example.com" {
		t.Errorf("answer name = %q, want %q", ans.Name, "example.com")
	}
	if ans.Type != TypeA {
		t.Errorf("answer type = %d, want %d (A)", ans.Type, TypeA)
	}
	if ans.TTL != 300 {
		t.Errorf("answer TTL = %d, want 300", ans.TTL)
	}
	if ans.ParsedData != "93.184.216.34" {
		t.Errorf("answer ParsedData = %q, want %q", ans.ParsedData, "93.184.216.34")
	}
}

func TestParseResponseWithAAAARecord(t *testing.T) {
	var buf []byte

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x5678)
	binary.BigEndian.PutUint16(header[2:4], FlagQR)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCount
	binary.BigEndian.PutUint16(header[6:8], 1) // ANCount
	buf = append(buf, header...)

	// Question
	nameBytes := encodeName("example.com")
	buf = append(buf, nameBytes...)
	qFooter := make([]byte, 4)
	binary.BigEndian.PutUint16(qFooter[0:2], TypeAAAA)
	binary.BigEndian.PutUint16(qFooter[2:4], ClassIN)
	buf = append(buf, qFooter...)

	// Answer: AAAA record
	buf = append(buf, encodeName("example.com")...)
	rrMeta := make([]byte, 10)
	binary.BigEndian.PutUint16(rrMeta[0:2], TypeAAAA)
	binary.BigEndian.PutUint16(rrMeta[2:4], ClassIN)
	binary.BigEndian.PutUint32(rrMeta[4:8], 600)
	binary.BigEndian.PutUint16(rrMeta[8:10], 16)
	buf = append(buf, rrMeta...)

	ipv6 := net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")
	buf = append(buf, ipv6.To16()...)

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
	}
	if msg.Answers[0].ParsedData != "2606:2800:220:1:248:1893:25c8:1946" {
		t.Errorf("AAAA ParsedData = %q, want %q", msg.Answers[0].ParsedData, "2606:2800:220:1:248:1893:25c8:1946")
	}
}

func TestDecodeName(t *testing.T) {
	// Simple name: \x07example\x03com\x00
	data := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	name, offset, err := decodeName(data, 0)
	if err != nil {
		t.Fatalf("decodeName failed: %v", err)
	}
	if name != "example.com" {
		t.Errorf("name = %q, want %q", name, "example.com")
	}
	if offset != len(data) {
		t.Errorf("offset = %d, want %d", offset, len(data))
	}
}

func TestDecodeNameWithPointer(t *testing.T) {
	// Data: at offset 0, name "com\x00", then at offset 5, a pointer to offset 0.
	data := []byte{
		3, 'c', 'o', 'm', 0, // offset 0-4: "com"
		0xC0, 0x00, // offset 5-6: pointer to offset 0
	}
	name, offset, err := decodeName(data, 5)
	if err != nil {
		t.Fatalf("decodeName with pointer failed: %v", err)
	}
	if name != "com" {
		t.Errorf("name = %q, want %q", name, "com")
	}
	if offset != 7 {
		t.Errorf("offset = %d, want 7", offset)
	}
}

func TestDecodeNameCompressionLoop(t *testing.T) {
	// A pointer that points to itself should be detected as a loop.
	data := []byte{0xC0, 0x00}
	_, _, err := decodeName(data, 0)
	if err == nil {
		t.Error("expected error for compression loop")
	}
}

func TestDecodeNameOutOfBounds(t *testing.T) {
	// Label length extends beyond data.
	data := []byte{5, 'a', 'b'}
	_, _, err := decodeName(data, 0)
	if err == nil {
		t.Error("expected error for label out of bounds")
	}
}

func TestDecodeNamePointerOutOfBounds(t *testing.T) {
	// Pointer byte but no second byte.
	data := []byte{0xC0}
	_, _, err := decodeName(data, 0)
	if err == nil {
		t.Error("expected error for pointer offset out of bounds")
	}
}

func TestDecodeNameEmptyInput(t *testing.T) {
	data := []byte{}
	_, _, err := decodeName(data, 0)
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParseTXT(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"single string", []byte{5, 'h', 'e', 'l', 'l', 'o'}, "hello"},
		{"two strings", []byte{3, 'f', 'o', 'o', 3, 'b', 'a', 'r'}, "foobar"},
		{"empty", []byte{}, ""},
		{"zero-length string", []byte{0}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTXT(tt.data)
			if got != tt.want {
				t.Errorf("parseTXT = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseResponseWithTXTRecord(t *testing.T) {
	var buf []byte

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x9999)
	binary.BigEndian.PutUint16(header[2:4], FlagQR)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCount
	binary.BigEndian.PutUint16(header[6:8], 1) // ANCount
	buf = append(buf, header...)

	// Question
	buf = append(buf, encodeName("example.com")...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], TypeTXT)
	binary.BigEndian.PutUint16(qf[2:4], ClassIN)
	buf = append(buf, qf...)

	// Answer: TXT record
	buf = append(buf, encodeName("example.com")...)
	txtData := []byte{11, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'}
	rrMeta := make([]byte, 10)
	binary.BigEndian.PutUint16(rrMeta[0:2], TypeTXT)
	binary.BigEndian.PutUint16(rrMeta[2:4], ClassIN)
	binary.BigEndian.PutUint32(rrMeta[4:8], 100)
	binary.BigEndian.PutUint16(rrMeta[8:10], uint16(len(txtData)))
	buf = append(buf, rrMeta...)
	buf = append(buf, txtData...)

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if msg.Answers[0].ParsedData != "hello world" {
		t.Errorf("TXT ParsedData = %q, want %q", msg.Answers[0].ParsedData, "hello world")
	}
}

func TestParseResponseWithNSRecord(t *testing.T) {
	var buf []byte

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xAAAA)
	binary.BigEndian.PutUint16(header[2:4], FlagQR)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCount
	binary.BigEndian.PutUint16(header[6:8], 0) // ANCount
	binary.BigEndian.PutUint16(header[8:10], 1) // NSCount
	buf = append(buf, header...)

	// Question
	buf = append(buf, encodeName("example.com")...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], TypeA)
	binary.BigEndian.PutUint16(qf[2:4], ClassIN)
	buf = append(buf, qf...)

	// Authority: NS record
	buf = append(buf, encodeName("example.com")...)
	nsName := encodeName("ns1.example.com")
	rrMeta := make([]byte, 10)
	binary.BigEndian.PutUint16(rrMeta[0:2], TypeNS)
	binary.BigEndian.PutUint16(rrMeta[2:4], ClassIN)
	binary.BigEndian.PutUint32(rrMeta[4:8], 3600)
	binary.BigEndian.PutUint16(rrMeta[8:10], uint16(len(nsName)))
	buf = append(buf, rrMeta...)
	buf = append(buf, nsName...)

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(msg.Authority) != 1 {
		t.Fatalf("expected 1 authority record, got %d", len(msg.Authority))
	}
	if msg.Authority[0].ParsedData != "ns1.example.com" {
		t.Errorf("NS ParsedData = %q, want %q", msg.Authority[0].ParsedData, "ns1.example.com")
	}
}

func TestParseQuestionSectionTooShort(t *testing.T) {
	// Valid header claiming 1 question, but the question data is truncated.
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCount = 1

	// Add a valid name but no type/class bytes.
	data := append(header, encodeName("example.com")...)

	_, err := Parse(data)
	if err == nil {
		t.Error("expected error when question section is too short")
	}
}

func TestParseResourceRecordTooShort(t *testing.T) {
	// Build a message with 1 answer but truncated RR data.
	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCount
	binary.BigEndian.PutUint16(header[6:8], 1) // ANCount
	buf = append(buf, header...)

	// Question
	buf = append(buf, encodeName("example.com")...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], TypeA)
	binary.BigEndian.PutUint16(qf[2:4], ClassIN)
	buf = append(buf, qf...)

	// Answer: just the name, not enough for the RR metadata
	buf = append(buf, encodeName("example.com")...)
	// Only 4 bytes instead of the required 10
	buf = append(buf, 0, 1, 0, 1)

	_, err := Parse(buf)
	if err == nil {
		t.Error("expected error when resource record is too short")
	}
}

func TestParseRDataBeyondMessage(t *testing.T) {
	// Build a response where rdlength claims more data than available.
	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCount
	binary.BigEndian.PutUint16(header[6:8], 1) // ANCount
	buf = append(buf, header...)

	// Question
	buf = append(buf, encodeName("example.com")...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], TypeA)
	binary.BigEndian.PutUint16(qf[2:4], ClassIN)
	buf = append(buf, qf...)

	// Answer with rdlength = 100 but no actual data
	buf = append(buf, encodeName("example.com")...)
	rrMeta := make([]byte, 10)
	binary.BigEndian.PutUint16(rrMeta[0:2], TypeA)
	binary.BigEndian.PutUint16(rrMeta[2:4], ClassIN)
	binary.BigEndian.PutUint32(rrMeta[4:8], 300)
	binary.BigEndian.PutUint16(rrMeta[8:10], 100) // rdlength = 100, way more than available
	buf = append(buf, rrMeta...)

	_, err := Parse(buf)
	if err == nil {
		t.Error("expected error when rdata extends beyond message")
	}
}

func TestHeaderFlags(t *testing.T) {
	// Test combined flags.
	h := &Header{Flags: FlagQR | FlagAA | FlagRD | FlagRA | RcodeNoError}
	if !h.IsResponse() {
		t.Error("expected IsResponse true")
	}
	if h.IsTruncated() {
		t.Error("expected IsTruncated false")
	}
	if h.Rcode() != RcodeNoError {
		t.Errorf("Rcode = %d, want %d", h.Rcode(), RcodeNoError)
	}
}

func TestParseRDataUnknownType(t *testing.T) {
	// Unknown type should produce "<rdata N bytes>" format.
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	result := parseRData(9999, data, 0, 4)
	if result != "<rdata 4 bytes>" {
		t.Errorf("parseRData for unknown type = %q, want %q", result, "<rdata 4 bytes>")
	}
}

func TestParseRDataAWrongLength(t *testing.T) {
	// A record with wrong length (not 4) should fall through to default.
	data := []byte{1, 2, 3}
	result := parseRData(TypeA, data, 0, 3)
	if result != "<rdata 3 bytes>" {
		t.Errorf("parseRData A with 3 bytes = %q, want %q", result, "<rdata 3 bytes>")
	}
}

func TestParseRDataAAAAWrongLength(t *testing.T) {
	data := make([]byte, 8)
	result := parseRData(TypeAAAA, data, 0, 8)
	if result != "<rdata 8 bytes>" {
		t.Errorf("parseRData AAAA with 8 bytes = %q, want %q", result, "<rdata 8 bytes>")
	}
}

func TestSerializeHeaderFields(t *testing.T) {
	msg := &Message{
		Header: Header{
			ID:      0xBEEF,
			Flags:   FlagRD,
			QDCount: 1,
		},
		Questions: []Question{
			{Name: "test.org", Type: TypeAAAA, Class: ClassIN},
		},
	}

	data, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// Verify header bytes.
	if binary.BigEndian.Uint16(data[0:2]) != 0xBEEF {
		t.Errorf("serialized ID = 0x%04x, want 0xBEEF", binary.BigEndian.Uint16(data[0:2]))
	}
	if binary.BigEndian.Uint16(data[2:4]) != FlagRD {
		t.Errorf("serialized Flags = 0x%04x, want 0x%04x", binary.BigEndian.Uint16(data[2:4]), FlagRD)
	}
}
