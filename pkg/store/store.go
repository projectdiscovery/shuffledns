// Package store provides an in-memory ip -> hostnames index used for
// deduplication and wildcard removal.
//
// It previously persisted to LevelDB on disk (with a JSON marshal and
// read-modify-write on every append plus background compaction). The native
// resolver streams structured results in-process, so an in-memory map is both
// simpler and considerably faster; the public API is kept stable.
package store

import (
	"sort"
	"sync"
)

// Store is an in-memory storage for ip based deduplication and wildcard removal.
type Store struct {
	mu   sync.RWMutex
	data map[string]map[string]struct{}
}

// New creates a new in-memory store. The path argument is accepted for API
// compatibility and ignored.
func New(_ string) (*Store, error) {
	return &Store{data: make(map[string]map[string]struct{})}, nil
}

// New creates a new ip-hostname pair in the map.
func (s *Store) New(ip, hostname string) error {
	return s.Append(ip, hostname)
}

// Exists indicates if an IP exists in the map.
func (s *Store) Exists(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.data[ip]
	return ok
}

// GetHostnames returns the comma separated hostnames stored for an IP.
func (s *Store) GetHostnames(ip string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hostnameMap, ok := s.data[ip]
	if !ok {
		return ""
	}
	hostnames := make([]string, 0, len(hostnameMap))
	for hostname := range hostnameMap {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)
	return joinComma(hostnames)
}

// Append adds one or more hostnames to an IP, deduplicating automatically.
func (s *Store) Append(ip string, hostnames ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hostnameMap, ok := s.data[ip]
	if !ok {
		hostnameMap = make(map[string]struct{}, len(hostnames))
		s.data[ip] = hostnameMap
	}
	for _, hostname := range hostnames {
		hostnameMap[hostname] = struct{}{}
	}
	return nil
}

// Delete removes the records for an IP from the store.
func (s *Store) Delete(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, ip)
	return nil
}

// Close releases all resources held by the store.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = nil
}

// Iterate walks every ip and its hostnames. counter is the number of distinct
// hostnames pointing at the ip (used by the wildcard heuristic).
func (s *Store) Iterate(f func(ip string, hostnames []string, counter int)) {
	// snapshot under lock to avoid holding it during the callback (which may
	// perform network I/O during wildcard filtering)
	s.mu.RLock()
	ips := make([]string, 0, len(s.data))
	snapshot := make(map[string][]string, len(s.data))
	for ip, hostnameMap := range s.data {
		hostnames := make([]string, 0, len(hostnameMap))
		for hostname := range hostnameMap {
			hostnames = append(hostnames, hostname)
		}
		sort.Strings(hostnames)
		snapshot[ip] = hostnames
		ips = append(ips, ip)
	}
	s.mu.RUnlock()

	// Iterate in sorted order so output is deterministic across runs (the map
	// backing replaced a LevelDB store that iterated in sorted key order).
	sort.Strings(ips)
	for _, ip := range ips {
		hostnames := snapshot[ip]
		f(ip, hostnames, len(hostnames))
	}
}

func joinComma(values []string) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	}
	n := len(values) - 1
	for _, v := range values {
		n += len(v)
	}
	out := make([]byte, 0, n)
	for i, v := range values {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, v...)
	}
	return string(out)
}
