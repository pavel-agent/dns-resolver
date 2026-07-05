package dns

import (
	"testing"
)

func TestRandIDVaries(t *testing.T) {
	// crypto/rand-backed IDs must not be a fixed sequence. Collect a batch and
	// assert we see more than one distinct value (a fixed generator would
	// produce all-identical or a predictable repeating value here).
	seen := make(map[uint16]bool)
	for i := 0; i < 100; i++ {
		seen[randID()] = true
	}
	if len(seen) < 2 {
		t.Errorf("randID produced only %d distinct values across 100 calls; expected variation", len(seen))
	}
}

func TestRemoveServer(t *testing.T) {
	servers := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}

	result := removeServer(servers, "8.8.8.8")
	if len(result) != 2 {
		t.Fatalf("removeServer returned %d servers, want 2", len(result))
	}
	for _, s := range result {
		if s == "8.8.8.8" {
			t.Error("removeServer did not remove the target server")
		}
	}
}

func TestRemoveServerNotFound(t *testing.T) {
	servers := []string{"1.1.1.1", "8.8.8.8"}

	result := removeServer(servers, "9.9.9.9")
	if len(result) != 2 {
		t.Fatalf("removeServer returned %d servers, want 2 (server not in list)", len(result))
	}
}

func TestRemoveServerAll(t *testing.T) {
	// If removing would leave an empty list, original is returned.
	servers := []string{"1.1.1.1"}

	result := removeServer(servers, "1.1.1.1")
	if len(result) != 1 {
		t.Fatalf("removeServer returned %d servers, want 1 (should return original when result would be empty)", len(result))
	}
}

func TestRemoveServerDoesNotMutateOriginal(t *testing.T) {
	servers := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	original := make([]string, len(servers))
	copy(original, servers)

	removeServer(servers, "8.8.8.8")

	for i, s := range servers {
		if s != original[i] {
			t.Errorf("removeServer mutated original slice at index %d: got %q, want %q", i, s, original[i])
		}
	}
}

func TestRemoveServerMultipleMatches(t *testing.T) {
	servers := []string{"1.1.1.1", "8.8.8.8", "1.1.1.1", "8.8.8.8"}

	result := removeServer(servers, "8.8.8.8")
	if len(result) != 2 {
		t.Fatalf("removeServer returned %d servers, want 2", len(result))
	}
	for _, s := range result {
		if s == "8.8.8.8" {
			t.Error("removeServer did not remove all instances")
		}
	}
}

func TestNewResolver(t *testing.T) {
	r := NewResolver(false)

	if r.Cache == nil {
		t.Error("NewResolver created resolver with nil Cache")
	}
	if r.Transport == nil {
		t.Error("NewResolver created resolver with nil Transport")
	}
	if r.Verbose {
		t.Error("NewResolver(false) created verbose resolver")
	}

	r2 := NewResolver(true)
	if !r2.Verbose {
		t.Error("NewResolver(true) created non-verbose resolver")
	}
}

func TestResolveMaxDepth(t *testing.T) {
	r := NewResolver(false)

	// Call the private resolve method with depth exceeding max.
	_, err := r.resolve("example.com", TypeA, maxDepth+1)
	if err == nil {
		t.Error("expected error when recursion depth exceeded")
	}
}

func TestResolveFromCache(t *testing.T) {
	r := NewResolver(false)

	// Pre-populate the cache.
	records := []ResourceRecord{
		{Name: "cached.example.com", Type: TypeA, TTL: 300, ParsedData: "10.0.0.1"},
	}
	r.Cache.Put("cached.example.com", TypeA, records)

	result, err := r.Resolve("cached.example.com", TypeA)
	if err != nil {
		t.Fatalf("Resolve from cache failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result))
	}
	if result[0].ParsedData != "10.0.0.1" {
		t.Errorf("ParsedData = %q, want %q", result[0].ParsedData, "10.0.0.1")
	}
}

func TestResolveFromCacheNormalizesName(t *testing.T) {
	r := NewResolver(false)

	// Cache with lowercase.
	records := []ResourceRecord{
		{Name: "example.com", Type: TypeA, TTL: 300, ParsedData: "10.0.0.1"},
	}
	r.Cache.Put("example.com", TypeA, records)

	// Query with uppercase -- should hit cache after normalization.
	result, err := r.Resolve("EXAMPLE.COM", TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result))
	}
}

func TestResolveFromCacheTrimsTrailingDot(t *testing.T) {
	r := NewResolver(false)

	records := []ResourceRecord{
		{Name: "example.com", Type: TypeA, TTL: 300, ParsedData: "10.0.0.1"},
	}
	r.Cache.Put("example.com", TypeA, records)

	// Query with trailing dot.
	result, err := r.Resolve("example.com.", TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result))
	}
}

func TestRootServersPopulated(t *testing.T) {
	if len(rootServers) == 0 {
		t.Error("rootServers is empty")
	}
	if len(rootServers) != 13 {
		t.Errorf("expected 13 root servers, got %d", len(rootServers))
	}
}
