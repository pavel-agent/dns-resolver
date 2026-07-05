package dns

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestNewTransport(t *testing.T) {
	tr := NewTransport()
	if tr == nil {
		t.Fatal("NewTransport returned nil")
	}
	if tr.Timeout != defaultTimeout {
		t.Errorf("Timeout = %v, want %v", tr.Timeout, defaultTimeout)
	}
	if tr.Port != "53" {
		t.Errorf("Port = %q, want %q", tr.Port, "53")
	}
}

func TestTransportPortDefault(t *testing.T) {
	tr := &Transport{}
	if tr.port() != "53" {
		t.Errorf("port() = %q, want %q", tr.port(), "53")
	}

	tr.Port = "5353"
	if tr.port() != "5353" {
		t.Errorf("port() = %q, want %q", tr.port(), "5353")
	}
}

// startMockDNSServers starts both a UDP and TCP DNS server on the same port,
// returning the port and cleanup function.
func startMockDNSServers(t *testing.T, handler func([]byte) []byte) (int, func()) {
	t.Helper()

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port

	tcpLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		udpConn.Close()
		t.Fatal(err)
	}

	// UDP handler
	go func() {
		buf := make([]byte, 512)
		for {
			n, remoteAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := handler(buf[:n])
			if resp != nil {
				udpConn.WriteToUDP(resp, remoteAddr)
			}
		}
	}()

	// TCP handler
	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				lenBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, lenBuf); err != nil {
					return
				}
				msgLen := binary.BigEndian.Uint16(lenBuf)
				msgBuf := make([]byte, msgLen)
				if _, err := io.ReadFull(c, msgBuf); err != nil {
					return
				}
				resp := handler(msgBuf)
				if resp != nil {
					respLen := make([]byte, 2)
					binary.BigEndian.PutUint16(respLen, uint16(len(resp)))
					c.Write(respLen)
					c.Write(resp)
				}
			}(conn)
		}
	}()

	return port, func() {
		udpConn.Close()
		tcpLn.Close()
	}
}

// parseFirstQuestion extracts the first question from a raw query, falling back
// to a default example.com/A question if parsing fails.
func parseFirstQuestion(queryData []byte) Question {
	if msg, err := Parse(queryData); err == nil && len(msg.Questions) > 0 {
		return msg.Questions[0]
	}
	return Question{Name: "example.com", Type: TypeA, Class: ClassIN}
}

// buildResponseFromQuery builds a DNS response for a query with an A record answer.
func buildResponseFromQuery(queryData []byte, ip net.IP, flags uint16) []byte {
	if len(queryData) < 12 {
		return nil
	}
	id := binary.BigEndian.Uint16(queryData[0:2])

	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], flags)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCount
	binary.BigEndian.PutUint16(header[6:8], 1) // ANCount
	buf = append(buf, header...)

	// Echo the question section from the query. We re-encode just the
	// question (rather than copying the raw tail) so that any additional-
	// section records in the query (e.g. an EDNS0 OPT record) are not
	// mistaken for the answer.
	q := parseFirstQuestion(queryData)
	buf = append(buf, encodeName(q.Name)...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], q.Type)
	binary.BigEndian.PutUint16(qf[2:4], q.Class)
	buf = append(buf, qf...)

	// Answer: A record.
	buf = append(buf, encodeName("example.com")...)
	rrMeta := make([]byte, 10)
	binary.BigEndian.PutUint16(rrMeta[0:2], TypeA)
	binary.BigEndian.PutUint16(rrMeta[2:4], ClassIN)
	binary.BigEndian.PutUint32(rrMeta[4:8], 300)
	binary.BigEndian.PutUint16(rrMeta[8:10], 4)
	buf = append(buf, rrMeta...)
	buf = append(buf, ip.To4()...)

	return buf
}

func TestTransportQueryUDP(t *testing.T) {
	expectedIP := net.IPv4(10, 20, 30, 40)

	port, cleanup := startMockDNSServers(t, func(data []byte) []byte {
		return buildResponseFromQuery(data, expectedIP, FlagQR)
	})
	defer cleanup()

	tr := &Transport{
		Timeout: 2 * time.Second,
		Port:    fmt.Sprintf("%d", port),
	}

	msg := NewQuery(0xABCD, "example.com", TypeA)
	resp, err := tr.queryUDP(msg, "127.0.0.1")
	if err != nil {
		t.Fatalf("queryUDP failed: %v", err)
	}

	if !resp.Header.IsResponse() {
		t.Error("expected response flag")
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
	if resp.Answers[0].ParsedData != "10.20.30.40" {
		t.Errorf("answer = %q, want %q", resp.Answers[0].ParsedData, "10.20.30.40")
	}
}

func TestTransportQueryTCP(t *testing.T) {
	expectedIP := net.IPv4(192, 168, 1, 1)

	port, cleanup := startMockDNSServers(t, func(data []byte) []byte {
		return buildResponseFromQuery(data, expectedIP, FlagQR)
	})
	defer cleanup()

	tr := &Transport{
		Timeout: 2 * time.Second,
		Port:    fmt.Sprintf("%d", port),
	}

	msg := NewQuery(0x5678, "example.com", TypeA)
	resp, err := tr.queryTCP(msg, "127.0.0.1")
	if err != nil {
		t.Fatalf("queryTCP failed: %v", err)
	}

	if !resp.Header.IsResponse() {
		t.Error("expected response flag")
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
	if resp.Answers[0].ParsedData != "192.168.1.1" {
		t.Errorf("answer = %q, want %q", resp.Answers[0].ParsedData, "192.168.1.1")
	}
}

func TestTransportQueryFallbackToTCP(t *testing.T) {
	// UDP returns truncated, TCP returns full response.
	expectedIP := net.IPv4(5, 6, 7, 8)

	// We need separate handlers for UDP and TCP.
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port

	tcpLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		udpConn.Close()
		t.Fatal(err)
	}
	defer udpConn.Close()
	defer tcpLn.Close()

	// UDP: return truncated response.
	go func() {
		buf := make([]byte, 512)
		for {
			n, remoteAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := buildResponseFromQuery(buf[:n], expectedIP, FlagQR|FlagTC)
			udpConn.WriteToUDP(resp, remoteAddr)
		}
	}()

	// TCP: return full response.
	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				lenBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, lenBuf); err != nil {
					return
				}
				msgLen := binary.BigEndian.Uint16(lenBuf)
				msgBuf := make([]byte, msgLen)
				if _, err := io.ReadFull(c, msgBuf); err != nil {
					return
				}
				resp := buildResponseFromQuery(msgBuf, expectedIP, FlagQR)
				respLen := make([]byte, 2)
				binary.BigEndian.PutUint16(respLen, uint16(len(resp)))
				c.Write(respLen)
				c.Write(resp)
			}(conn)
		}
	}()

	tr := &Transport{
		Timeout: 2 * time.Second,
		Port:    fmt.Sprintf("%d", port),
	}

	msg := NewQuery(0x9999, "example.com", TypeA)
	resp, err := tr.Query(msg, "127.0.0.1")
	if err != nil {
		t.Fatalf("Query with TCP fallback failed: %v", err)
	}

	// Should get the TCP response (not truncated).
	if resp.Header.IsTruncated() {
		t.Error("expected non-truncated response after TCP fallback")
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
	if resp.Answers[0].ParsedData != "5.6.7.8" {
		t.Errorf("answer = %q, want %q", resp.Answers[0].ParsedData, "5.6.7.8")
	}
}

func TestTransportQueryNonTruncated(t *testing.T) {
	// Normal UDP response, no TCP fallback needed.
	expectedIP := net.IPv4(1, 2, 3, 4)

	port, cleanup := startMockDNSServers(t, func(data []byte) []byte {
		return buildResponseFromQuery(data, expectedIP, FlagQR)
	})
	defer cleanup()

	tr := &Transport{
		Timeout: 2 * time.Second,
		Port:    fmt.Sprintf("%d", port),
	}

	msg := NewQuery(0x1111, "example.com", TypeA)
	resp, err := tr.Query(msg, "127.0.0.1")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if resp.Header.IsTruncated() {
		t.Error("expected non-truncated response")
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
	if resp.Answers[0].ParsedData != "1.2.3.4" {
		t.Errorf("answer = %q, want %q", resp.Answers[0].ParsedData, "1.2.3.4")
	}
}

func TestTransportQueryUDPInvalidServer(t *testing.T) {
	tr := &Transport{Timeout: 100 * time.Millisecond, Port: "53"}
	msg := NewQuery(0x1234, "example.com", TypeA)

	_, err := tr.queryUDP(msg, "192.0.2.1") // TEST-NET, non-routable
	if err == nil {
		t.Error("expected error querying unreachable server")
	}
}

func TestTransportQueryTCPInvalidServer(t *testing.T) {
	tr := &Transport{Timeout: 100 * time.Millisecond, Port: "53"}
	msg := NewQuery(0x1234, "example.com", TypeA)

	_, err := tr.queryTCP(msg, "192.0.2.1")
	if err == nil {
		t.Error("expected error querying unreachable TCP server")
	}
}

func TestTransportQueryUDPError(t *testing.T) {
	// Query method should propagate UDP errors.
	tr := &Transport{Timeout: 100 * time.Millisecond, Port: "53"}
	msg := NewQuery(0x1234, "example.com", TypeA)

	_, err := tr.Query(msg, "192.0.2.1")
	if err == nil {
		t.Error("expected error from Query with unreachable server")
	}
}

func TestTransportQueryTCPFallbackError(t *testing.T) {
	// UDP returns truncated, but TCP also fails.
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	defer udpConn.Close()
	// No TCP listener on this port -- TCP will fail.

	go func() {
		buf := make([]byte, 512)
		for {
			n, remoteAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := buildResponseFromQuery(buf[:n], net.IPv4(1, 1, 1, 1), FlagQR|FlagTC)
			udpConn.WriteToUDP(resp, remoteAddr)
		}
	}()

	tr := &Transport{
		Timeout: 500 * time.Millisecond,
		Port:    fmt.Sprintf("%d", port),
	}

	msg := NewQuery(0x2222, "example.com", TypeA)
	_, err = tr.Query(msg, "127.0.0.1")
	if err == nil {
		t.Error("expected error when TCP fallback fails")
	}
}

func TestReadFull(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	expected := []byte("hello world")

	go func() {
		// Write in small chunks.
		for i := 0; i < len(expected); i++ {
			server.Write(expected[i : i+1])
			time.Sleep(1 * time.Millisecond)
		}
	}()

	buf := make([]byte, len(expected))
	n, err := readFull(client, buf)
	if err != nil {
		t.Fatalf("readFull failed: %v", err)
	}
	if n != len(expected) {
		t.Errorf("readFull read %d bytes, want %d", n, len(expected))
	}
	if string(buf) != string(expected) {
		t.Errorf("readFull got %q, want %q", string(buf), string(expected))
	}
}

func TestReadFullEarlyEOF(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		server.Write([]byte("hi"))
		server.Close()
	}()

	buf := make([]byte, 10)
	n, err := readFull(client, buf)
	if err == nil {
		t.Error("expected error from readFull when connection closes early")
	}
	if n != 2 {
		t.Errorf("readFull read %d bytes, want 2", n)
	}
}

func TestReadFullEmptyBuffer(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	buf := make([]byte, 0)
	n, err := readFull(client, buf)
	if err != nil {
		t.Fatalf("readFull with empty buffer failed: %v", err)
	}
	if n != 0 {
		t.Errorf("readFull read %d bytes, want 0", n)
	}
}

func TestTransportQueryTCPServerClosesAfterLengthPrefix(t *testing.T) {
	// TCP server sends length prefix but then closes connection before the body.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read the query.
				lenBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, lenBuf); err != nil {
					return
				}
				msgLen := binary.BigEndian.Uint16(lenBuf)
				msgBuf := make([]byte, msgLen)
				if _, err := io.ReadFull(c, msgBuf); err != nil {
					return
				}
				// Send length prefix claiming 100 bytes, then close.
				respLen := make([]byte, 2)
				binary.BigEndian.PutUint16(respLen, 100)
				c.Write(respLen)
				// Close without sending the body.
			}(conn)
		}
	}()

	tr := &Transport{Timeout: 2 * time.Second, Port: fmt.Sprintf("%d", port)}
	msg := NewQuery(0x3333, "example.com", TypeA)
	_, err = tr.queryTCP(msg, "127.0.0.1")
	if err == nil {
		t.Error("expected error when TCP server closes after length prefix")
	}
}

func TestTransportQueryTCPServerSendsGarbage(t *testing.T) {
	// TCP server sends a valid length prefix but garbage data.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				lenBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, lenBuf); err != nil {
					return
				}
				msgLen := binary.BigEndian.Uint16(lenBuf)
				msgBuf := make([]byte, msgLen)
				if _, err := io.ReadFull(c, msgBuf); err != nil {
					return
				}
				// Send length prefix + garbage that isn't valid DNS.
				garbage := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
				respLen := make([]byte, 2)
				binary.BigEndian.PutUint16(respLen, uint16(len(garbage)))
				c.Write(respLen)
				c.Write(garbage)
			}(conn)
		}
	}()

	tr := &Transport{Timeout: 2 * time.Second, Port: fmt.Sprintf("%d", port)}
	msg := NewQuery(0x4444, "example.com", TypeA)
	_, err = tr.queryTCP(msg, "127.0.0.1")
	if err == nil {
		t.Error("expected error when TCP server sends garbage response")
	}
}

func TestTransportQueryTCPServerClosesImmediately(t *testing.T) {
	// TCP server accepts connection then closes immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close() // Close immediately.
		}
	}()

	tr := &Transport{Timeout: 2 * time.Second, Port: fmt.Sprintf("%d", port)}
	msg := NewQuery(0x5555, "example.com", TypeA)
	_, err = tr.queryTCP(msg, "127.0.0.1")
	if err == nil {
		t.Error("expected error when TCP server closes immediately")
	}
}

func TestTransportQueryUDPServerSendsGarbage(t *testing.T) {
	// UDP server responds with garbage that can't be parsed.
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	defer udpConn.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			_, remoteAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Send garbage that's too short to be a valid DNS message.
			udpConn.WriteToUDP([]byte{0xFF, 0xFF}, remoteAddr)
		}
	}()

	tr := &Transport{Timeout: 2 * time.Second, Port: fmt.Sprintf("%d", port)}
	msg := NewQuery(0x6666, "example.com", TypeA)
	_, err = tr.queryUDP(msg, "127.0.0.1")
	if err == nil {
		t.Error("expected error when UDP server sends garbage response")
	}
}
