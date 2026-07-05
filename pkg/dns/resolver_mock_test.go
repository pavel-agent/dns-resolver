package dns

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mockDNSServer is a DNS server for testing that responds based on a handler function.
type mockDNSServer struct {
	udpConn *net.UDPConn
	tcpLn   net.Listener
	port    int
}

// newMockDNSServer starts a mock DNS server on a random port with both UDP and TCP.
func newMockDNSServer(t *testing.T, handler func(req *Message) *Message) *mockDNSServer {
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

	s := &mockDNSServer{udpConn: udpConn, tcpLn: tcpLn, port: port}

	// UDP handler.
	go func() {
		buf := make([]byte, 512)
		for {
			n, remoteAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req, err := Parse(buf[:n])
			if err != nil {
				continue
			}
			resp := handler(req)
			if resp == nil {
				continue
			}
			data, err := serializeFullMessage(resp)
			if err != nil {
				continue
			}
			udpConn.WriteToUDP(data, remoteAddr)
		}
	}()

	// TCP handler.
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
				req, err := Parse(msgBuf)
				if err != nil {
					return
				}
				resp := handler(req)
				if resp == nil {
					return
				}
				data, err := serializeFullMessage(resp)
				if err != nil {
					return
				}
				respLen := make([]byte, 2)
				binary.BigEndian.PutUint16(respLen, uint16(len(data)))
				c.Write(respLen)
				c.Write(data)
			}(conn)
		}
	}()

	return s
}

func (s *mockDNSServer) close() {
	s.udpConn.Close()
	s.tcpLn.Close()
}

// serializeFullMessage serializes a complete DNS message including all sections.
func serializeFullMessage(msg *Message) ([]byte, error) {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], msg.Header.ID)
	binary.BigEndian.PutUint16(buf[2:4], msg.Header.Flags)
	binary.BigEndian.PutUint16(buf[4:6], msg.Header.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], msg.Header.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], msg.Header.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], msg.Header.ARCount)

	for _, q := range msg.Questions {
		buf = append(buf, encodeName(q.Name)...)
		b := make([]byte, 4)
		binary.BigEndian.PutUint16(b[0:2], q.Type)
		binary.BigEndian.PutUint16(b[2:4], q.Class)
		buf = append(buf, b...)
	}

	serializeRRs := func(rrs []ResourceRecord) {
		for _, rr := range rrs {
			buf = append(buf, encodeName(rr.Name)...)
			meta := make([]byte, 10)
			binary.BigEndian.PutUint16(meta[0:2], rr.Type)
			binary.BigEndian.PutUint16(meta[2:4], rr.Class)
			binary.BigEndian.PutUint32(meta[4:8], rr.TTL)
			binary.BigEndian.PutUint16(meta[8:10], uint16(len(rr.RData)))
			buf = append(buf, meta...)
			buf = append(buf, rr.RData...)
		}
	}

	serializeRRs(msg.Answers)
	serializeRRs(msg.Authority)
	serializeRRs(msg.Additional)

	return buf, nil
}

// makeARecord creates a ResourceRecord for an A record.
func makeARecord(name string, ip net.IP, ttl uint32) ResourceRecord {
	return ResourceRecord{
		Name:       name,
		Type:       TypeA,
		Class:      ClassIN,
		TTL:        ttl,
		RData:      ip.To4(),
		ParsedData: ip.String(),
	}
}

// makeNSRecord creates a ResourceRecord for an NS record.
func makeNSRecord(name, nsName string, ttl uint32) ResourceRecord {
	return ResourceRecord{
		Name:       name,
		Type:       TypeNS,
		Class:      ClassIN,
		TTL:        ttl,
		RData:      encodeName(nsName),
		ParsedData: nsName,
	}
}

// makeCNAMERecord creates a ResourceRecord for a CNAME record.
func makeCNAMERecord(name, target string, ttl uint32) ResourceRecord {
	return ResourceRecord{
		Name:       name,
		Type:       TypeCNAME,
		Class:      ClassIN,
		TTL:        ttl,
		RData:      encodeName(target),
		ParsedData: target,
	}
}

// makeAAAARecord creates a ResourceRecord for an AAAA record.
func makeAAAARecord(name string, ip net.IP, ttl uint32) ResourceRecord {
	return ResourceRecord{
		Name:       name,
		Type:       TypeAAAA,
		Class:      ClassIN,
		TTL:        ttl,
		RData:      ip.To16(),
		ParsedData: ip.String(),
	}
}

// newMockDNSServerV6 starts a mock DNS server bound to the IPv6 loopback
// (::1), used to exercise AAAA glue / IPv6 nameserver handling.
func newMockDNSServerV6(t *testing.T, handler func(req *Message) *Message) *mockDNSServer {
	t.Helper()

	udpAddr, err := net.ResolveUDPAddr("udp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port

	tcpLn, err := net.Listen("tcp", fmt.Sprintf("[::1]:%d", port))
	if err != nil {
		udpConn.Close()
		t.Skipf("IPv6 loopback TCP unavailable: %v", err)
	}

	s := &mockDNSServer{udpConn: udpConn, tcpLn: tcpLn, port: port}

	go func() {
		buf := make([]byte, 512)
		for {
			n, remoteAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req, err := Parse(buf[:n])
			if err != nil {
				continue
			}
			resp := handler(req)
			if resp == nil {
				continue
			}
			data, err := serializeFullMessage(resp)
			if err != nil {
				continue
			}
			udpConn.WriteToUDP(data, remoteAddr)
		}
	}()

	return s
}

// newTestResolver creates a resolver that uses the given mock server.
func newTestResolver(server *mockDNSServer, verbose bool) *Resolver {
	return &Resolver{
		Cache: NewCache(),
		Transport: &Transport{
			Timeout: 2 * time.Second,
			Port:    fmt.Sprintf("%d", server.port),
		},
		Verbose: verbose,
	}
}

// TestResolverDirectAnswer tests direct answer from DNS server.
func TestResolverDirectAnswer(t *testing.T) {
	expectedIP := net.IPv4(93, 184, 216, 34)

	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR,
				QDCount: 1,
				ANCount: 1,
			},
			Questions: []Question{q},
			Answers: []ResourceRecord{
				makeARecord(q.Name, expectedIP, 300),
			},
		}
	})
	defer server.close()

	// We need to override rootServers so the resolver queries our mock.
	// Since rootServers is a package-level variable, we save and restore it.
	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, false)
	result, err := r.Resolve("example.com", TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if result[0].ParsedData != "93.184.216.34" {
		t.Errorf("got %q, want %q", result[0].ParsedData, "93.184.216.34")
	}
}

// TestResolverNXDOMAIN tests NXDOMAIN error handling.
func TestResolverNXDOMAIN(t *testing.T) {
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR | RcodeNXDomain,
				QDCount: 1,
			},
			Questions: []Question{q},
		}
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, false)
	_, err := r.Resolve("nonexistent.example.com", TypeA)
	if err == nil {
		t.Fatal("expected NXDOMAIN error")
	}
	if !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Errorf("expected NXDOMAIN in error, got: %v", err)
	}
}

// TestResolverDNSError tests non-zero rcode error handling (e.g., SERVFAIL).
func TestResolverDNSError(t *testing.T) {
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR | RcodeServFail,
				QDCount: 1,
			},
			Questions: []Question{q},
		}
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, false)
	_, err := r.Resolve("fail.example.com", TypeA)
	if err == nil {
		t.Fatal("expected DNS error")
	}
	if !strings.Contains(err.Error(), "rcode") {
		t.Errorf("expected rcode in error, got: %v", err)
	}
}

// TestResolverCNAMEFollowing tests CNAME chain following.
func TestResolverCNAMEFollowing(t *testing.T) {
	// www.example.com CNAME -> example.com -> 93.184.216.34
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		name := strings.ToLower(q.Name)

		if name == "www.example.com" && q.Type == TypeA {
			// Return CNAME answer.
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: []Question{q},
				Answers: []ResourceRecord{
					makeCNAMERecord("www.example.com", "example.com", 300),
				},
			}
		}

		if name == "example.com" && q.Type == TypeA {
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: []Question{q},
				Answers: []ResourceRecord{
					makeARecord("example.com", net.IPv4(93, 184, 216, 34), 300),
				},
			}
		}

		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR | RcodeNXDomain,
				QDCount: 1,
			},
			Questions: []Question{q},
		}
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, false)
	result, err := r.Resolve("www.example.com", TypeA)
	if err != nil {
		t.Fatalf("Resolve CNAME failed: %v", err)
	}

	// Should have CNAME + A record.
	if len(result) < 2 {
		t.Fatalf("expected at least 2 results (CNAME + A), got %d", len(result))
	}

	// First result should be CNAME.
	if result[0].Type != TypeCNAME {
		t.Errorf("first result type = %d, want CNAME (%d)", result[0].Type, TypeCNAME)
	}

	// Last result should be A record.
	lastResult := result[len(result)-1]
	if lastResult.Type != TypeA {
		t.Errorf("last result type = %d, want A (%d)", lastResult.Type, TypeA)
	}
	if lastResult.ParsedData != "93.184.216.34" {
		t.Errorf("A record = %q, want %q", lastResult.ParsedData, "93.184.216.34")
	}
}

// TestResolverReferralWithGlue tests following NS referrals with glue records.
func TestResolverReferralWithGlue(t *testing.T) {
	var testQueryCount atomic.Int64

	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		name := strings.ToLower(q.Name)

		if name == "test.example.com" && q.Type == TypeA {
			count := testQueryCount.Add(1)
			if count == 1 {
				// First query: return referral with glue.
				return &Message{
					Header: Header{
						ID:      req.Header.ID,
						Flags:   FlagQR,
						QDCount: 1,
						NSCount: 1,
						ARCount: 1,
					},
					Questions: []Question{q},
					Authority: []ResourceRecord{
						makeNSRecord("example.com", "ns1.example.com", 3600),
					},
					Additional: []ResourceRecord{
						makeARecord("ns1.example.com", net.IPv4(127, 0, 0, 1), 3600),
					},
				}
			}
			// Second query (after following referral): return the answer.
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: []Question{q},
				Answers: []ResourceRecord{
					makeARecord(q.Name, net.IPv4(93, 184, 216, 34), 300),
				},
			}
		}

		return nil
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, true) // verbose mode

	result, err := r.Resolve("test.example.com", TypeA)
	if err != nil {
		t.Fatalf("Resolve with glue referral failed: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if result[0].ParsedData != "93.184.216.34" {
		t.Errorf("got %q, want %q", result[0].ParsedData, "93.184.216.34")
	}
}

// TestResolverReferralWithAAAAGlue tests following an NS referral whose glue
// records are AAAA (IPv6) rather than A.
func TestResolverReferralWithAAAAGlue(t *testing.T) {
	var testQueryCount atomic.Int64

	server := newMockDNSServerV6(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		name := strings.ToLower(q.Name)

		if name == "test.example.com" && q.Type == TypeA {
			count := testQueryCount.Add(1)
			if count == 1 {
				// First query: referral with AAAA glue only.
				return &Message{
					Header: Header{
						ID:      req.Header.ID,
						Flags:   FlagQR,
						QDCount: 1,
						NSCount: 1,
						ARCount: 1,
					},
					Questions: []Question{q},
					Authority: []ResourceRecord{
						makeNSRecord("example.com", "ns1.example.com", 3600),
					},
					Additional: []ResourceRecord{
						makeAAAARecord("ns1.example.com", net.IPv6loopback, 3600),
					},
				}
			}
			// Second query (after following AAAA glue): return the answer.
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: []Question{q},
				Answers: []ResourceRecord{
					makeARecord(q.Name, net.IPv4(93, 184, 216, 34), 300),
				},
			}
		}

		return nil
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"::1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, true)

	result, err := r.Resolve("test.example.com", TypeA)
	if err != nil {
		t.Fatalf("Resolve with AAAA glue referral failed: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if result[0].ParsedData != "93.184.216.34" {
		t.Errorf("got %q, want %q", result[0].ParsedData, "93.184.216.34")
	}
	if testQueryCount.Load() < 2 {
		t.Errorf("expected the AAAA glue to be followed (>=2 queries), got %d", testQueryCount.Load())
	}
}

// TestResolverReferralWithoutGlue tests following NS referrals without glue records.
func TestResolverReferralWithoutGlue(t *testing.T) {
	var targetQueryCount atomic.Int64

	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		name := strings.ToLower(q.Name)

		// Query for the target domain: first time return referral, second time return answer.
		if name == "target.example.com" && q.Type == TypeA {
			count := targetQueryCount.Add(1)
			if count == 1 {
				// First query: return NS referral without glue.
				return &Message{
					Header: Header{
						ID:      req.Header.ID,
						Flags:   FlagQR,
						QDCount: 1,
						NSCount: 1,
					},
					Questions: []Question{q},
					Authority: []ResourceRecord{
						makeNSRecord("example.com", "ns1.example.com", 3600),
					},
				}
			}
			// Subsequent queries: return the answer.
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: []Question{q},
				Answers: []ResourceRecord{
					makeARecord(q.Name, net.IPv4(10, 0, 0, 1), 300),
				},
			}
		}

		// Query to resolve ns1.example.com: return its A record.
		if name == "ns1.example.com" && q.Type == TypeA {
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: []Question{q},
				Answers: []ResourceRecord{
					makeARecord("ns1.example.com", net.IPv4(127, 0, 0, 1), 3600),
				},
			}
		}

		// Fallback: return an A record for anything else.
		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR,
				QDCount: 1,
				ANCount: 1,
			},
			Questions: []Question{q},
			Answers: []ResourceRecord{
				makeARecord(q.Name, net.IPv4(10, 0, 0, 1), 300),
			},
		}
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, true) // verbose mode to exercise logging paths
	result, err := r.Resolve("target.example.com", TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected at least 1 result")
	}
}

// TestResolverNoAnswersNoReferrals tests "resolution stuck" error.
func TestResolverNoAnswersNoReferrals(t *testing.T) {
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		// Return an empty response: no answers, no authority.
		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR,
				QDCount: 1,
			},
			Questions: []Question{q},
		}
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, false)
	_, err := r.Resolve("stuck.example.com", TypeA)
	if err == nil {
		t.Fatal("expected 'resolution stuck' error")
	}
	if !strings.Contains(err.Error(), "stuck") {
		t.Errorf("expected 'stuck' in error, got: %v", err)
	}
}

// TestResolverServerError tests retry behavior when a server returns an error.
func TestResolverServerErrorRetry(t *testing.T) {
	// Since rootServers has one entry, a transport error should cause failure
	// (not retry, because there's only one server).
	origRootServers := rootServers
	rootServers = []string{"192.0.2.1"} // non-routable
	defer func() { rootServers = origRootServers }()

	r := &Resolver{
		Cache: NewCache(),
		Transport: &Transport{
			Timeout: 100 * time.Millisecond,
			Port:    "53",
		},
		Verbose: true,
	}

	_, err := r.Resolve("example.com", TypeA)
	if err == nil {
		t.Fatal("expected error with non-routable server")
	}
}

// TestResolverServerErrorRetryMultiple tests retry with multiple servers.
// When a query fails and multiple nameservers are available, the resolver
// should remove the bad server and retry with the remaining ones.
func TestResolverServerErrorRetryMultiple(t *testing.T) {
	goodIP := net.IPv4(42, 42, 42, 42)

	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR,
				QDCount: 1,
				ANCount: 1,
			},
			Questions: []Question{q},
			Answers: []ResourceRecord{
				makeARecord(q.Name, goodIP, 300),
			},
		}
	})
	defer server.close()

	origRootServers := rootServers
	// Multiple bad servers before the good one to maximize probability
	// of exercising the retry path (len(nameservers) > 1 branch).
	rootServers = []string{
		"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4",
		"192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8",
		"127.0.0.1",
	}
	defer func() { rootServers = origRootServers }()

	r := &Resolver{
		Cache: NewCache(),
		Transport: &Transport{
			Timeout: 50 * time.Millisecond, // Very short timeout for fast test.
			Port:    fmt.Sprintf("%d", server.port),
		},
		Verbose: true,
	}

	result, err := r.Resolve("retry.example.com", TypeA)
	if err != nil {
		t.Fatalf("Resolve failed (expected retry to succeed): %v", err)
	}
	if len(result) != 1 || result[0].ParsedData != "42.42.42.42" {
		t.Errorf("expected 42.42.42.42, got %v", result)
	}
}

// TestResolverVerboseMode tests verbose output paths.
func TestResolverVerboseMode(t *testing.T) {
	r := NewResolver(true)

	// Pre-populate cache.
	records := []ResourceRecord{
		makeARecord("verbose-test.com", net.IPv4(1, 2, 3, 4), 300),
	}
	r.Cache.Put("verbose-test.com", TypeA, records)

	result, err := r.Resolve("verbose-test.com", TypeA)
	if err != nil {
		t.Fatalf("Resolve with verbose mode failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
}

// TestResolverMaxDepthError tests the recursion depth limit.
func TestResolverMaxDepthError(t *testing.T) {
	r := NewResolver(false)

	_, err := r.resolve("deep.example.com", TypeA, maxDepth+1)
	if err == nil {
		t.Fatal("expected error for exceeding max depth")
	}
	if !strings.Contains(err.Error(), "maximum recursion depth exceeded") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestResolverCachesResults tests that resolved records are cached.
func TestResolverCachesResults(t *testing.T) {
	r := NewResolver(false)

	records := []ResourceRecord{
		makeARecord("cached.com", net.IPv4(10, 0, 0, 1), 300),
	}
	r.Cache.Put("cached.com", TypeA, records)

	result1, err := r.Resolve("cached.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}

	result2, err := r.Resolve("cached.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}

	if len(result1) != len(result2) {
		t.Errorf("cached results differ in length: %d vs %d", len(result1), len(result2))
	}
}

// TestResolverNameNormalization tests name normalization.
func TestResolverNameNormalization(t *testing.T) {
	r := NewResolver(false)

	records := []ResourceRecord{
		makeARecord("normalize.com", net.IPv4(1, 1, 1, 1), 300),
	}
	r.Cache.Put("normalize.com", TypeA, records)

	tests := []string{
		"NORMALIZE.COM",
		"Normalize.Com",
		"normalize.com.",
		"NORMALIZE.COM.",
	}

	for _, name := range tests {
		result, err := r.Resolve(name, TypeA)
		if err != nil {
			t.Errorf("Resolve(%q) failed: %v", name, err)
			continue
		}
		if len(result) != 1 {
			t.Errorf("Resolve(%q) returned %d results, want 1", name, len(result))
		}
	}
}

// TestRemoveServerEmpty tests removeServer with empty input.
func TestRemoveServerEmptyInput(t *testing.T) {
	var servers []string
	result := removeServer(servers, "1.1.1.1")
	if len(result) != 0 {
		t.Errorf("expected 0 servers, got %d", len(result))
	}
}

// TestParseResponseMXRecord tests parsing MX records.
func TestParseResponseMXRecord(t *testing.T) {
	var buf []byte

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xBBBB)
	binary.BigEndian.PutUint16(header[2:4], FlagQR)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCount
	binary.BigEndian.PutUint16(header[6:8], 1) // ANCount
	buf = append(buf, header...)

	buf = append(buf, encodeName("example.com")...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], TypeMX)
	binary.BigEndian.PutUint16(qf[2:4], ClassIN)
	buf = append(buf, qf...)

	buf = append(buf, encodeName("example.com")...)
	mxNameBytes := encodeName("mail.example.com")
	mxRdata := make([]byte, 2+len(mxNameBytes))
	binary.BigEndian.PutUint16(mxRdata[0:2], 10)
	copy(mxRdata[2:], mxNameBytes)

	rrMeta := make([]byte, 10)
	binary.BigEndian.PutUint16(rrMeta[0:2], TypeMX)
	binary.BigEndian.PutUint16(rrMeta[2:4], ClassIN)
	binary.BigEndian.PutUint32(rrMeta[4:8], 3600)
	binary.BigEndian.PutUint16(rrMeta[8:10], uint16(len(mxRdata)))
	buf = append(buf, rrMeta...)
	buf = append(buf, mxRdata...)

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
	}

	expected := "10 mail.example.com"
	if msg.Answers[0].ParsedData != expected {
		t.Errorf("MX ParsedData = %q, want %q", msg.Answers[0].ParsedData, expected)
	}
}

// TestParseResponseCNAMERecord tests parsing CNAME records.
func TestParseResponseCNAMERecord(t *testing.T) {
	var buf []byte

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xCCCC)
	binary.BigEndian.PutUint16(header[2:4], FlagQR)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCount
	binary.BigEndian.PutUint16(header[6:8], 1) // ANCount
	buf = append(buf, header...)

	buf = append(buf, encodeName("www.example.com")...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], TypeCNAME)
	binary.BigEndian.PutUint16(qf[2:4], ClassIN)
	buf = append(buf, qf...)

	buf = append(buf, encodeName("www.example.com")...)
	cnameRdata := encodeName("example.com")
	rrMeta := make([]byte, 10)
	binary.BigEndian.PutUint16(rrMeta[0:2], TypeCNAME)
	binary.BigEndian.PutUint16(rrMeta[2:4], ClassIN)
	binary.BigEndian.PutUint32(rrMeta[4:8], 300)
	binary.BigEndian.PutUint16(rrMeta[8:10], uint16(len(cnameRdata)))
	buf = append(buf, rrMeta...)
	buf = append(buf, cnameRdata...)

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
	}
	if msg.Answers[0].ParsedData != "example.com" {
		t.Errorf("CNAME ParsedData = %q, want %q", msg.Answers[0].ParsedData, "example.com")
	}
}

// TestParseResponseWithAdditionalRecords tests parsing additional records.
func TestParseResponseWithAdditionalRecords(t *testing.T) {
	var buf []byte

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xDDDD)
	binary.BigEndian.PutUint16(header[2:4], FlagQR)
	binary.BigEndian.PutUint16(header[4:6], 1)  // QDCount
	binary.BigEndian.PutUint16(header[8:10], 1)  // NSCount
	binary.BigEndian.PutUint16(header[10:12], 1) // ARCount
	buf = append(buf, header...)

	buf = append(buf, encodeName("example.com")...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], TypeA)
	binary.BigEndian.PutUint16(qf[2:4], ClassIN)
	buf = append(buf, qf...)

	// Authority NS.
	buf = append(buf, encodeName("example.com")...)
	nsRdata := encodeName("ns1.example.com")
	nsMeta := make([]byte, 10)
	binary.BigEndian.PutUint16(nsMeta[0:2], TypeNS)
	binary.BigEndian.PutUint16(nsMeta[2:4], ClassIN)
	binary.BigEndian.PutUint32(nsMeta[4:8], 3600)
	binary.BigEndian.PutUint16(nsMeta[8:10], uint16(len(nsRdata)))
	buf = append(buf, nsMeta...)
	buf = append(buf, nsRdata...)

	// Additional A record.
	buf = append(buf, encodeName("ns1.example.com")...)
	aMeta := make([]byte, 10)
	binary.BigEndian.PutUint16(aMeta[0:2], TypeA)
	binary.BigEndian.PutUint16(aMeta[2:4], ClassIN)
	binary.BigEndian.PutUint32(aMeta[4:8], 3600)
	binary.BigEndian.PutUint16(aMeta[8:10], 4)
	buf = append(buf, aMeta...)
	buf = append(buf, net.IPv4(10, 0, 0, 53).To4()...)

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(msg.Authority) != 1 {
		t.Fatalf("expected 1 authority, got %d", len(msg.Authority))
	}
	if len(msg.Additional) != 1 {
		t.Fatalf("expected 1 additional, got %d", len(msg.Additional))
	}
}

// TestParseRDataMXTooShort tests MX with insufficient data.
func TestParseRDataMXTooShort(t *testing.T) {
	data := []byte{0, 10}
	result := parseRData(TypeMX, data, 0, 2)
	if result != "<rdata 2 bytes>" {
		t.Errorf("parseRData MX too short = %q, want %q", result, "<rdata 2 bytes>")
	}
}

// TestParseRDataCNAMEError tests CNAME with corrupt name data.
func TestParseRDataCNAMEError(t *testing.T) {
	data := []byte{0xC0, 0xFF}
	result := parseRData(TypeCNAME, data, 0, 2)
	if result != "<rdata 2 bytes>" {
		t.Errorf("parseRData CNAME error = %q, want %q", result, "<rdata 2 bytes>")
	}
}

// TestParseRDataNSError tests NS with corrupt name data.
func TestParseRDataNSError(t *testing.T) {
	data := []byte{0xC0, 0xFF}
	result := parseRData(TypeNS, data, 0, 2)
	if result != "<rdata 2 bytes>" {
		t.Errorf("parseRData NS error = %q, want %q", result, "<rdata 2 bytes>")
	}
}

// TestParseTXTTruncated tests TXT with truncated string data.
func TestParseTXTTruncated(t *testing.T) {
	data := []byte{10, 'a', 'b', 'c'}
	result := parseTXT(data)
	if result != "" {
		t.Errorf("parseTXT truncated = %q, want %q", result, "")
	}
}

// TestParseTXTMultipleStrings tests TXT with multiple strings.
func TestParseTXTMultipleStrings(t *testing.T) {
	data := []byte{3, 'a', 'b', 'c', 2, 'd', 'e', 4, 'f', 'g', 'h', 'i'}
	result := parseTXT(data)
	if result != "abcdefghi" {
		t.Errorf("parseTXT = %q, want %q", result, "abcdefghi")
	}
}

// TestParseAuthoritySectionError tests error in authority section.
func TestParseAuthoritySectionError(t *testing.T) {
	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:6], 1)  // QDCount
	binary.BigEndian.PutUint16(header[8:10], 1)  // NSCount = 1 but no data
	buf = append(buf, header...)

	buf = append(buf, encodeName("example.com")...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], TypeA)
	binary.BigEndian.PutUint16(qf[2:4], ClassIN)
	buf = append(buf, qf...)

	_, err := Parse(buf)
	if err == nil {
		t.Error("expected error for missing authority section")
	}
	if !strings.Contains(err.Error(), "authority") {
		t.Errorf("expected authority error, got: %v", err)
	}
}

// TestParseAdditionalSectionError tests error in additional section.
func TestParseAdditionalSectionError(t *testing.T) {
	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:6], 1)   // QDCount
	binary.BigEndian.PutUint16(header[10:12], 1)  // ARCount = 1 but no data
	buf = append(buf, header...)

	buf = append(buf, encodeName("example.com")...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], TypeA)
	binary.BigEndian.PutUint16(qf[2:4], ClassIN)
	buf = append(buf, qf...)

	_, err := Parse(buf)
	if err == nil {
		t.Error("expected error for missing additional section")
	}
	if !strings.Contains(err.Error(), "additional") {
		t.Errorf("expected additional error, got: %v", err)
	}
}

// TestParseQuestionNameError tests corrupt question name.
func TestParseQuestionNameError(t *testing.T) {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:6], 1)
	data := append(header, 0xC0, 0xFF)
	_, err := Parse(data)
	if err == nil {
		t.Error("expected error for corrupt question name")
	}
}

// TestParseRRNameError tests corrupt RR name.
func TestParseRRNameError(t *testing.T) {
	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:6], 1)
	binary.BigEndian.PutUint16(header[6:8], 1)
	buf = append(buf, header...)

	buf = append(buf, encodeName("example.com")...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], TypeA)
	binary.BigEndian.PutUint16(qf[2:4], ClassIN)
	buf = append(buf, qf...)

	buf = append(buf, 0xC0, 0xFF) // Corrupt name.

	_, err := Parse(buf)
	if err == nil {
		t.Error("expected error for corrupt RR name")
	}
}

// TestDecodeNameMultiLabel tests multi-label name decoding.
func TestDecodeNameMultiLabel(t *testing.T) {
	data := encodeName("a.b.c.d.e.f")
	name, offset, err := decodeName(data, 0)
	if err != nil {
		t.Fatalf("decodeName failed: %v", err)
	}
	if name != "a.b.c.d.e.f" {
		t.Errorf("name = %q, want %q", name, "a.b.c.d.e.f")
	}
	if offset != len(data) {
		t.Errorf("offset = %d, want %d", offset, len(data))
	}
}

// TestDecodeNameWithPointerInMiddle tests pointer in middle of name.
func TestDecodeNameWithPointerInMiddle(t *testing.T) {
	data := []byte{
		3, 'c', 'o', 'm', 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0xC0, 0x00,
	}
	name, offset, err := decodeName(data, 5)
	if err != nil {
		t.Fatalf("decodeName failed: %v", err)
	}
	if name != "example.com" {
		t.Errorf("name = %q, want %q", name, "example.com")
	}
	if offset != 15 {
		t.Errorf("offset = %d, want 15", offset)
	}
}

// TestEncodeNameLongLabels tests encoding long labels.
func TestEncodeNameLongLabels(t *testing.T) {
	longLabel := strings.Repeat("a", 63)
	name := longLabel + ".com"
	encoded := encodeName(name)

	if encoded[0] != 63 {
		t.Errorf("first label length = %d, want 63", encoded[0])
	}

	decoded, _, err := decodeName(encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != name {
		t.Errorf("roundtrip = %q, want %q", decoded, name)
	}
}

// TestSerializeNoQuestions tests serializing message with no questions.
func TestSerializeNoQuestions(t *testing.T) {
	msg := &Message{Header: Header{ID: 0x1111, QDCount: 0}}

	data, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 12 {
		t.Errorf("length = %d, want 12", len(data))
	}

	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Questions) != 0 {
		t.Errorf("questions = %d, want 0", len(parsed.Questions))
	}
}

// TestParseResponseWithMultipleAnswers tests multiple A record answers.
func TestParseResponseWithMultipleAnswers(t *testing.T) {
	var buf []byte

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xEEEE)
	binary.BigEndian.PutUint16(header[2:4], FlagQR)
	binary.BigEndian.PutUint16(header[4:6], 1)
	binary.BigEndian.PutUint16(header[6:8], 3) // 3 answers
	buf = append(buf, header...)

	buf = append(buf, encodeName("example.com")...)
	qf := make([]byte, 4)
	binary.BigEndian.PutUint16(qf[0:2], TypeA)
	binary.BigEndian.PutUint16(qf[2:4], ClassIN)
	buf = append(buf, qf...)

	ips := []net.IP{net.IPv4(1, 1, 1, 1), net.IPv4(2, 2, 2, 2), net.IPv4(3, 3, 3, 3)}
	for _, ip := range ips {
		buf = append(buf, encodeName("example.com")...)
		rrMeta := make([]byte, 10)
		binary.BigEndian.PutUint16(rrMeta[0:2], TypeA)
		binary.BigEndian.PutUint16(rrMeta[2:4], ClassIN)
		binary.BigEndian.PutUint32(rrMeta[4:8], 300)
		binary.BigEndian.PutUint16(rrMeta[8:10], 4)
		buf = append(buf, rrMeta...)
		buf = append(buf, ip.To4()...)
	}

	msg, err := Parse(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) != 3 {
		t.Fatalf("expected 3 answers, got %d", len(msg.Answers))
	}

	expected := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	for i, ans := range msg.Answers {
		if ans.ParsedData != expected[i] {
			t.Errorf("answer[%d] = %q, want %q", i, ans.ParsedData, expected[i])
		}
	}
}

// TestResolverDifferentRecordTypes tests resolution from cache for various types.
func TestResolverDifferentRecordTypes(t *testing.T) {
	r := NewResolver(false)

	tests := []struct {
		name    string
		qtype   uint16
		records []ResourceRecord
	}{
		{"aaaa.test", TypeAAAA, []ResourceRecord{{Name: "aaaa.test", Type: TypeAAAA, TTL: 300, ParsedData: "::1"}}},
		{"ns.test", TypeNS, []ResourceRecord{{Name: "ns.test", Type: TypeNS, TTL: 300, ParsedData: "ns1.test"}}},
		{"cname.test", TypeCNAME, []ResourceRecord{{Name: "cname.test", Type: TypeCNAME, TTL: 300, ParsedData: "real.test"}}},
		{"mx.test", TypeMX, []ResourceRecord{{Name: "mx.test", Type: TypeMX, TTL: 300, ParsedData: "10 mail.test"}}},
		{"txt.test", TypeTXT, []ResourceRecord{{Name: "txt.test", Type: TypeTXT, TTL: 300, ParsedData: "v=spf1"}}},
	}

	for _, tt := range tests {
		t.Run(TypeToString(tt.qtype), func(t *testing.T) {
			r.Cache.Put(tt.name, tt.qtype, tt.records)
			result, err := r.Resolve(tt.name, tt.qtype)
			if err != nil {
				t.Fatal(err)
			}
			if len(result) != 1 || result[0].ParsedData != tt.records[0].ParsedData {
				t.Errorf("got %v, want %v", result, tt.records)
			}
		})
	}
}

// TestResolverMultipleAnswers tests that multiple A records are returned.
func TestResolverMultipleAnswers(t *testing.T) {
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR,
				QDCount: 1,
				ANCount: 3,
			},
			Questions: []Question{q},
			Answers: []ResourceRecord{
				makeARecord(q.Name, net.IPv4(1, 1, 1, 1), 300),
				makeARecord(q.Name, net.IPv4(2, 2, 2, 2), 300),
				makeARecord(q.Name, net.IPv4(3, 3, 3, 3), 300),
			},
		}
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, false)
	result, err := r.Resolve("multi.example.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result))
	}
}

// TestResolverAnswersOfDifferentType tests responses with answers that don't match qtype.
func TestResolverAnswersOfDifferentType(t *testing.T) {
	// Return answers that don't match the query type and have no CNAME.
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		// Return an AAAA record when A is queried (not a CNAME).
		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR,
				QDCount: 1,
				ANCount: 1,
			},
			Questions: []Question{q},
			Answers: []ResourceRecord{
				{
					Name:       q.Name,
					Type:       TypeAAAA,
					Class:      ClassIN,
					TTL:        300,
					RData:      net.ParseIP("::1").To16(),
					ParsedData: "::1",
				},
			},
		}
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, false)
	_, err := r.Resolve("mismatch.example.com", TypeA)
	// Should get stuck since answers don't match and there are no referrals.
	if err == nil {
		t.Error("expected error for mismatched answer types")
	}
}

// TestResolverTooManyReferrals tests the "too many referrals" error.
func TestResolverTooManyReferrals(t *testing.T) {
	// Always return referrals, never answers.
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR,
				QDCount: 1,
				NSCount: 1,
				ARCount: 1,
			},
			Questions: []Question{q},
			Authority: []ResourceRecord{
				makeNSRecord("example.com", "ns1.example.com", 3600),
			},
			Additional: []ResourceRecord{
				makeARecord("ns1.example.com", net.IPv4(127, 0, 0, 1), 3600),
			},
		}
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, false)
	_, err := r.Resolve("loop.example.com", TypeA)
	if err == nil {
		t.Fatal("expected 'too many referrals' error")
	}
	if !strings.Contains(err.Error(), "too many referrals") {
		t.Errorf("expected 'too many referrals' error, got: %v", err)
	}
}

// TestResolverCNAMEQueryForCNAME tests querying for CNAME type specifically.
func TestResolverCNAMEQueryForCNAME(t *testing.T) {
	// When querying for CNAME type, should return the CNAME record directly.
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR,
				QDCount: 1,
				ANCount: 1,
			},
			Questions: []Question{q},
			Answers: []ResourceRecord{
				makeCNAMERecord(q.Name, "real.example.com", 300),
			},
		}
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, false)
	result, err := r.Resolve("alias.example.com", TypeCNAME)
	if err != nil {
		t.Fatalf("Resolve CNAME failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if result[0].Type != TypeCNAME {
		t.Errorf("type = %d, want CNAME", result[0].Type)
	}
}

// TestResolverReferralNSResolutionFails tests referral where NS resolution fails.
func TestResolverReferralNSResolutionFails(t *testing.T) {
	// Return referral without glue, and the NS name resolution also fails.
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		name := strings.ToLower(q.Name)

		if name == "stuck2.example.com" {
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					NSCount: 1,
				},
				Questions: []Question{q},
				Authority: []ResourceRecord{
					makeNSRecord("example.com", "ns-unreachable.example.com", 3600),
				},
			}
		}

		// NS resolution: return NXDOMAIN.
		return &Message{
			Header: Header{
				ID:      req.Header.ID,
				Flags:   FlagQR | RcodeNXDomain,
				QDCount: 1,
			},
			Questions: []Question{q},
		}
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, true) // verbose for coverage
	_, err := r.Resolve("stuck2.example.com", TypeA)
	if err == nil {
		t.Fatal("expected error when NS resolution fails")
	}
}

// TestConstantValues tests DNS constant values.
func TestConstantValues(t *testing.T) {
	if ClassIN != 1 {
		t.Errorf("ClassIN = %d, want 1", ClassIN)
	}
	if maxDepth != 20 {
		t.Errorf("maxDepth = %d, want 20", maxDepth)
	}
	if maxUDPSize != 512 {
		t.Errorf("maxUDPSize = %d, want 512", maxUDPSize)
	}
	if defaultTimeout != 5*time.Second {
		t.Errorf("defaultTimeout = %v, want 5s", defaultTimeout)
	}
}

// TestResolverCNAMEChainCachesResult tests that CNAME results are cached.
func TestResolverCNAMEChainCachesResult(t *testing.T) {
	var callCount atomic.Int64
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		name := strings.ToLower(q.Name)
		callCount.Add(1)

		if name == "alias.cache.com" && q.Type == TypeA {
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: []Question{q},
				Answers: []ResourceRecord{
					makeCNAMERecord("alias.cache.com", "real.cache.com", 300),
				},
			}
		}
		if name == "real.cache.com" && q.Type == TypeA {
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: []Question{q},
				Answers: []ResourceRecord{
					makeARecord("real.cache.com", net.IPv4(9, 9, 9, 9), 300),
				},
			}
		}
		return nil
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, false)

	// First resolve.
	result1, err := r.Resolve("alias.cache.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	firstCallCount := callCount.Load()

	// Second resolve should hit cache.
	result2, err := r.Resolve("alias.cache.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}

	if callCount.Load() != firstCallCount {
		t.Errorf("second call made %d more queries (expected 0, cache should hit)", callCount.Load()-firstCallCount)
	}

	if len(result1) != len(result2) {
		t.Errorf("results differ: %d vs %d", len(result1), len(result2))
	}
}

// TestResolverCNAMEVerbose tests CNAME following with verbose mode enabled.
func TestResolverCNAMEVerbose(t *testing.T) {
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		name := strings.ToLower(q.Name)

		if name == "www.verbose.com" && q.Type == TypeA {
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: []Question{q},
				Answers: []ResourceRecord{
					makeCNAMERecord("www.verbose.com", "verbose.com", 300),
				},
			}
		}
		if name == "verbose.com" && q.Type == TypeA {
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: []Question{q},
				Answers: []ResourceRecord{
					makeARecord("verbose.com", net.IPv4(1, 2, 3, 4), 300),
				},
			}
		}
		return nil
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, true) // verbose = true to cover the CNAME verbose log line
	result, err := r.Resolve("www.verbose.com", TypeA)
	if err != nil {
		t.Fatalf("Resolve CNAME verbose failed: %v", err)
	}
	if len(result) < 2 {
		t.Fatalf("expected at least 2 results (CNAME + A), got %d", len(result))
	}
}

// TestResolverCNAMEResolutionError tests CNAME resolution failure.
func TestResolverCNAMEResolutionError(t *testing.T) {
	server := newMockDNSServer(t, func(req *Message) *Message {
		if len(req.Questions) == 0 {
			return nil
		}
		q := req.Questions[0]
		name := strings.ToLower(q.Name)

		if name == "alias.fail.com" && q.Type == TypeA {
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR,
					QDCount: 1,
					ANCount: 1,
				},
				Questions: []Question{q},
				Answers: []ResourceRecord{
					makeCNAMERecord("alias.fail.com", "target.fail.com", 300),
				},
			}
		}
		// target.fail.com returns NXDOMAIN.
		if name == "target.fail.com" && q.Type == TypeA {
			return &Message{
				Header: Header{
					ID:      req.Header.ID,
					Flags:   FlagQR | RcodeNXDomain,
					QDCount: 1,
				},
				Questions: []Question{q},
			}
		}
		return nil
	})
	defer server.close()

	origRootServers := rootServers
	rootServers = []string{"127.0.0.1"}
	defer func() { rootServers = origRootServers }()

	r := newTestResolver(server, false)
	_, err := r.Resolve("alias.fail.com", TypeA)
	if err == nil {
		t.Fatal("expected error when CNAME target resolution fails")
	}
	if !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Errorf("expected NXDOMAIN error, got: %v", err)
	}
}
