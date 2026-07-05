package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	defaultTimeout = 5 * time.Second
	// maxUDPSize is the legacy non-EDNS0 UDP message limit (RFC 1035).
	maxUDPSize = 512
	// udpReadBufferSize matches the EDNS0 UDP payload size we advertise in
	// queries, so larger (non-truncated) EDNS0 responses are read fully
	// instead of being silently clipped by a 512-byte buffer.
	udpReadBufferSize = int(defaultUDPSize)
)

// Transport handles sending DNS queries and receiving responses over UDP and TCP.
type Transport struct {
	Timeout time.Duration
	Port    string // DNS server port; defaults to "53".
}

// NewTransport creates a new Transport with the default timeout.
func NewTransport() *Transport {
	return &Transport{
		Timeout: defaultTimeout,
		Port:    "53",
	}
}

// port returns the configured port, defaulting to "53".
func (t *Transport) port() string {
	if t.Port == "" {
		return "53"
	}
	return t.Port
}

// Query sends a DNS query to the given server and returns the parsed response.
// It first tries UDP, and falls back to TCP if the response is truncated.
func (t *Transport) Query(msg *Message, server string) (*Message, error) {
	resp, err := t.queryUDP(msg, server)
	if err != nil {
		return nil, err
	}

	// If truncated, retry over TCP.
	if resp.Header.IsTruncated() {
		resp, err = t.queryTCP(msg, server)
		if err != nil {
			return nil, fmt.Errorf("tcp fallback: %w", err)
		}
	}

	return resp, nil
}

// queryUDP sends a query over UDP.
func (t *Transport) queryUDP(msg *Message, server string) (*Message, error) {
	data, err := msg.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serializing query: %w", err)
	}

	addr := net.JoinHostPort(server, t.port())
	conn, err := net.DialTimeout("udp", addr, t.Timeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s via udp: %w", server, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(t.Timeout))

	_, err = conn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("sending query: %w", err)
	}

	buf := make([]byte, udpReadBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	resp, err := Parse(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return resp, nil
}

// queryTCP sends a query over TCP with length-prefixed framing.
func (t *Transport) queryTCP(msg *Message, server string) (*Message, error) {
	data, err := msg.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serializing query: %w", err)
	}

	addr := net.JoinHostPort(server, t.port())
	conn, err := net.DialTimeout("tcp", addr, t.Timeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s via tcp: %w", server, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(t.Timeout))

	// TCP DNS messages are prefixed with a 2-byte length.
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(data)))
	_, err = conn.Write(append(lenBuf, data...))
	if err != nil {
		return nil, fmt.Errorf("sending query: %w", err)
	}

	// Read the 2-byte length prefix.
	_, err = readFull(conn, lenBuf)
	if err != nil {
		return nil, fmt.Errorf("reading response length: %w", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf)

	// Read the response body.
	respBuf := make([]byte, respLen)
	_, err = readFull(conn, respBuf)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	resp, err := Parse(respBuf)
	if err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return resp, nil
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
