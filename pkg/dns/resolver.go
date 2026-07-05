package dns

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
)

// Root DNS servers (IPv4 addresses).
var rootServers = []string{
	"198.41.0.4",     // a.root-servers.net
	"199.9.14.201",   // b.root-servers.net
	"192.33.4.12",    // c.root-servers.net
	"199.7.91.13",    // d.root-servers.net
	"192.203.230.10", // e.root-servers.net
	"192.5.5.241",    // f.root-servers.net
	"192.112.36.4",   // g.root-servers.net
	"198.97.190.53",  // h.root-servers.net
	"192.36.148.17",  // i.root-servers.net
	"192.58.128.30",  // j.root-servers.net
	"193.0.14.129",   // k.root-servers.net
	"199.7.83.42",    // l.root-servers.net
	"202.12.27.33",   // m.root-servers.net
}

const maxDepth = 20

// Resolver performs recursive DNS resolution.
type Resolver struct {
	Cache     *Cache
	Transport *Transport
	Verbose   bool
}

// NewResolver creates a new Resolver with a cache and transport.
func NewResolver(verbose bool) *Resolver {
	return &Resolver{
		Cache:     NewCache(),
		Transport: NewTransport(),
		Verbose:   verbose,
	}
}

// Resolve recursively resolves a domain name for the given record type.
func (r *Resolver) Resolve(name string, qtype uint16) ([]ResourceRecord, error) {
	return r.resolve(name, qtype, 0)
}

func (r *Resolver) resolve(name string, qtype uint16, depth int) ([]ResourceRecord, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("maximum recursion depth exceeded resolving %s", name)
	}

	// Normalize name.
	name = strings.TrimSuffix(strings.ToLower(name), ".")

	// Check cache.
	if cached := r.Cache.Get(name, qtype); cached != nil {
		if r.Verbose {
			fmt.Printf("[cache hit] %s %s\n", name, TypeToString(qtype))
		}
		return cached, nil
	}

	// Start from root servers.
	nameservers := rootServers

	if r.Verbose {
		fmt.Printf("[resolve] %s %s (depth=%d)\n", name, TypeToString(qtype), depth)
	}

	for i := 0; i < maxDepth; i++ {
		// Pick a random nameserver from the list.
		server := nameservers[rand.Intn(len(nameservers))]

		if r.Verbose {
			fmt.Printf("  [query] %s %s -> %s\n", name, TypeToString(qtype), server)
		}

		id := randID()
		query := NewQuery(id, name, qtype)
		resp, err := r.Transport.Query(query, server)
		if err != nil {
			if r.Verbose {
				fmt.Printf("  [error] %s: %v\n", server, err)
			}
			// Try next server if available.
			if len(nameservers) > 1 {
				nameservers = removeServer(nameservers, server)
				continue
			}
			return nil, fmt.Errorf("query to %s failed: %w", server, err)
		}

		// Check for errors in response.
		rcode := resp.Header.Rcode()
		if rcode == RcodeNXDomain {
			return nil, fmt.Errorf("NXDOMAIN: %s does not exist", name)
		}
		if rcode != RcodeNoError {
			return nil, fmt.Errorf("DNS error: rcode=%d", rcode)
		}

		// Check for answers.
		if len(resp.Answers) > 0 {
			var results []ResourceRecord
			for _, ans := range resp.Answers {
				if ans.Type == qtype {
					results = append(results, ans)
				}
				// Follow CNAMEs.
				if ans.Type == TypeCNAME && qtype != TypeCNAME {
					if r.Verbose {
						fmt.Printf("  [cname] %s -> %s\n", name, ans.ParsedData)
					}
					cnameResults, err := r.resolve(ans.ParsedData, qtype, depth+1)
					if err != nil {
						return nil, err
					}
					// Prepend the CNAME record itself.
					results = append([]ResourceRecord{ans}, cnameResults...)
					r.Cache.Put(name, qtype, results)
					return results, nil
				}
			}
			if len(results) > 0 {
				r.Cache.Put(name, qtype, results)
				return results, nil
			}
		}

		// No answers -- look for referrals in authority section.
		if len(resp.Authority) > 0 {
			var newNS []string

			// First, try to find glue records (A records in additional section).
			for _, auth := range resp.Authority {
				if auth.Type == TypeNS {
					nsName := auth.ParsedData
					for _, add := range resp.Additional {
						if add.Type == TypeA && strings.EqualFold(add.Name, nsName) {
							newNS = append(newNS, add.ParsedData)
						}
					}
				}
			}

			// If we found glue records, use them.
			if len(newNS) > 0 {
				if r.Verbose {
					fmt.Printf("  [referral] following %d nameservers\n", len(newNS))
				}
				nameservers = newNS
				continue
			}

			// No glue records -- need to resolve the NS names.
			for _, auth := range resp.Authority {
				if auth.Type == TypeNS {
					nsName := auth.ParsedData
					if r.Verbose {
						fmt.Printf("  [resolve ns] %s\n", nsName)
					}
					nsRecords, err := r.resolve(nsName, TypeA, depth+1)
					if err != nil {
						continue
					}
					for _, ns := range nsRecords {
						if ns.Type == TypeA {
							newNS = append(newNS, ns.ParsedData)
						}
					}
				}
			}

			if len(newNS) > 0 {
				nameservers = newNS
				continue
			}
		}

		// No answers, no referrals.
		return nil, fmt.Errorf("resolution stuck for %s", name)
	}

	return nil, fmt.Errorf("too many referrals resolving %s", name)
}

// removeServer returns a copy of servers with the given server removed.
// randID returns a cryptographically-random 16-bit DNS transaction ID. The
// transaction ID is one of the few entropy sources protecting UDP DNS against
// off-path spoofing, so it must not come from the predictable, default-seeded
// math/rand generator. Falls back to math/rand only if crypto/rand fails.
func randID() uint16 {
	var b [2]byte
	if _, err := crand.Read(b[:]); err != nil {
		return uint16(rand.Intn(65536))
	}
	return binary.BigEndian.Uint16(b[:])
}

func removeServer(servers []string, server string) []string {
	var result []string
	for _, s := range servers {
		if s != server {
			result = append(result, s)
		}
	}
	if len(result) == 0 {
		return servers
	}
	return result
}
