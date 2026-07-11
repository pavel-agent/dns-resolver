package dns

import (
	"strings"
	"sync"
	"time"
)

// CacheEntry holds a cached DNS response with expiry.
type CacheEntry struct {
	Records   []ResourceRecord
	ExpiresAt time.Time
}

// delegationEntry holds cached nameserver addresses for a zone.
type delegationEntry struct {
	Servers   []string
	ExpiresAt time.Time
}

// Cache provides thread-safe DNS response caching with TTL expiry.
type Cache struct {
	mu          sync.RWMutex
	entries     map[string]*CacheEntry
	delegations map[string]*delegationEntry
}

// NewCache creates a new empty cache.
func NewCache() *Cache {
	return &Cache{
		entries:     make(map[string]*CacheEntry),
		delegations: make(map[string]*delegationEntry),
	}
}

// cacheKey builds a cache key from name and type.
func cacheKey(name string, qtype uint16) string {
	return name + ":" + TypeToString(qtype)
}

// Get retrieves cached records for a name and type, returning nil if not found or expired.
func (c *Cache) Get(name string, qtype uint16) []ResourceRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := cacheKey(name, qtype)
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil
	}

	// Return a copy to prevent mutation.
	result := make([]ResourceRecord, len(entry.Records))
	copy(result, entry.Records)
	return result
}

// Put stores records in the cache. TTL is derived from the minimum TTL of the records.
func (c *Cache) Put(name string, qtype uint16, records []ResourceRecord) {
	if len(records) == 0 {
		return
	}

	// Find minimum TTL.
	minTTL := records[0].TTL
	for _, rr := range records[1:] {
		if rr.TTL < minTTL {
			minTTL = rr.TTL
		}
	}

	// Enforce a minimum cache time of 30 seconds.
	if minTTL < 30 {
		minTTL = 30
	}

	entry := &CacheEntry{
		Records:   make([]ResourceRecord, len(records)),
		ExpiresAt: time.Now().Add(time.Duration(minTTL) * time.Second),
	}
	copy(entry.Records, records)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[cacheKey(name, qtype)] = entry
}

// Purge removes all expired entries (both answer and delegation caches).
func (c *Cache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
		}
	}
	for key, entry := range c.delegations {
		if now.After(entry.ExpiresAt) {
			delete(c.delegations, key)
		}
	}
}

// StartPurgeLoop launches a background goroutine that periodically purges
// expired entries so the cache maps do not grow without bound in a
// long-running process. Callers may cancel the loop by closing stop.
func (c *Cache) StartPurgeLoop(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.Purge()
			case <-stop:
				return
			}
		}
	}()
}

// PutDelegation caches the nameserver addresses responsible for a zone so that
// subsequent queries can start from the deepest known delegation instead of
// walking from the root servers every time. TTL is the minimum record TTL
// observed for the delegation, floored at 30 seconds.
func (c *Cache) PutDelegation(zone string, servers []string, minTTL uint32) {
	if len(servers) == 0 {
		return
	}
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	if minTTL < 30 {
		minTTL = 30
	}

	entry := &delegationEntry{
		Servers:   append([]string(nil), servers...),
		ExpiresAt: time.Now().Add(time.Duration(minTTL) * time.Second),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.delegations[zone] = entry
}

// GetDelegation returns the cached nameserver addresses for the deepest
// ancestor zone of name that has a live delegation, along with that zone. It
// returns (nil, "") when no usable delegation is cached.
func (c *Cache) GetDelegation(name string) ([]string, string) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")

	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	// Walk from the full name up the label hierarchy toward the root, returning
	// the first (deepest) live delegation found.
	labels := strings.Split(name, ".")
	for i := 0; i < len(labels); i++ {
		zone := strings.Join(labels[i:], ".")
		if entry, ok := c.delegations[zone]; ok && now.Before(entry.ExpiresAt) {
			return append([]string(nil), entry.Servers...), zone
		}
	}
	return nil, ""
}
