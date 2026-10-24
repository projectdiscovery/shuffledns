package store

import (
	"encoding/json"
	"os"
	"strings"

	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const Megabyte = 1 << 20

// resolverPrefix namespaces resolver-tracking entries inside the
// leveldb store so they don't collide with the IP -> hostnames
// records used for wildcard removal.
const resolverPrefix = "r:"

// Store is a storage for ip based wildcard removal
type Store struct {
	DB *leveldb.DB
}

// New creates a new storage for ip based wildcard removal
func New(dbPath string) (*Store, error) {
	storeDb, err := os.MkdirTemp(dbPath, "shuffledns-db-")
	if err != nil {
		return nil, err
	}
	db, err := leveldb.OpenFile(storeDb, &opt.Options{
		// Optimize for disk space reduction
		CompactionTableSize:    64 * Megabyte, // Reduced from 256MB for more frequent compaction
		WriteBuffer:            2 * Megabyte,  // Reduced from 4MB for more frequent flushing
		WriteL0SlowdownTrigger: 4,             // Trigger slowdown earlier
		WriteL0PauseTrigger:    8,             // Trigger pause earlier
		BlockSize:              2 * 1024,      // Reduced from 4KB for better compression of small records
		BlockCacheCapacity:     4 * Megabyte,  // Reduced from 8MB to lower memory usage
	})
	if err != nil {
		return nil, err
	}
	return &Store{DB: db}, nil
}

// New creates a new ip-hostname pair in the map
func (s *Store) New(ip, hostname string) error {
	hostnameMap := map[string]struct{}{hostname: {}}
	jsonData, err := json.Marshal(hostnameMap)
	if err != nil {
		return err
	}
	return s.DB.Put([]byte(ip), jsonData, nil)
}

// Exists indicates if an IP exists in the map
func (s *Store) Exists(ip string) bool {
	ok, err := s.DB.Has([]byte(ip), nil)
	return err == nil && ok
}

// Get gets the meta-information for an IP address from the map.
func (s *Store) GetHostnames(ip string) string {
	data, err := s.DB.Get([]byte(ip), nil)
	if err != nil {
		return ""
	}

	var hostnameMap map[string]struct{}
	if err := json.Unmarshal(data, &hostnameMap); err != nil {
		return ""
	}

	return strings.Join(mapsutil.GetKeys(hostnameMap), ",")
}

func (s *Store) Append(ip string, hostnames ...string) error {
	// Get existing hostnames
	var hostnameMap map[string]struct{}
	existingData, err := s.DB.Get([]byte(ip), nil)
	if err == nil && len(existingData) > 0 {
		if err := json.Unmarshal(existingData, &hostnameMap); err != nil {
			// If unmarshaling fails, start with empty map
			hostnameMap = make(map[string]struct{})
		}
	} else {
		hostnameMap = make(map[string]struct{})
	}

	// Add new hostnames to map (automatic deduplication)
	for _, hostname := range hostnames {
		hostnameMap[hostname] = struct{}{}
	}

	// Marshal and store
	jsonData, err := json.Marshal(hostnameMap)
	if err != nil {
		return err
	}

	return s.DB.Put([]byte(ip), jsonData, nil)
}

// Delete deletes the records for an IP from store.
func (s *Store) Delete(ip string) error {
	return s.DB.Delete([]byte(ip), nil)
}

func (s *Store) Close() {
	_ = s.DB.Close()
}

func (s *Store) Iterate(f func(ip string, hostnames []string, counter int)) {
	iter := s.DB.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		// Skip resolver-tracking entries; only iterate IP -> hostnames records.
		if strings.HasPrefix(key, resolverPrefix) {
			continue
		}

		var hostnameMap map[string]struct{}
		if err := json.Unmarshal(iter.Value(), &hostnameMap); err != nil {
			continue
		}

		// Convert map keys to slice
		hostnames := make([]string, 0, len(hostnameMap))
		for hostname := range hostnameMap {
			hostnames = append(hostnames, hostname)
		}

		counter := len(hostnames)
		f(key, hostnames, counter)
	}
}

// AppendResolvers records the resolver(s) that were observed answering
// for the given hostname. Empty resolver entries are ignored so the
// store stays consistent when massdns output lacks the metadata line.
func (s *Store) AppendResolvers(hostname string, resolvers ...string) error {
	filtered := resolvers[:0]
	for _, r := range resolvers {
		if r != "" {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) == 0 {
		return nil
	}

	key := []byte(resolverPrefix + hostname)
	var resolverMap map[string]struct{}
	existing, err := s.DB.Get(key, nil)
	if err == nil && len(existing) > 0 {
		if err := json.Unmarshal(existing, &resolverMap); err != nil {
			resolverMap = make(map[string]struct{})
		}
	} else {
		resolverMap = make(map[string]struct{})
	}

	for _, r := range filtered {
		resolverMap[r] = struct{}{}
	}

	data, err := json.Marshal(resolverMap)
	if err != nil {
		return err
	}
	return s.DB.Put(key, data, nil)
}

// GetResolvers returns the deduplicated list of resolver IPs that
// produced answers for the given hostname. The returned slice is
// nil when no resolvers were recorded for the hostname.
func (s *Store) GetResolvers(hostname string) []string {
	data, err := s.DB.Get([]byte(resolverPrefix+hostname), nil)
	if err != nil || len(data) == 0 {
		return nil
	}
	var resolverMap map[string]struct{}
	if err := json.Unmarshal(data, &resolverMap); err != nil {
		return nil
	}
	if len(resolverMap) == 0 {
		return nil
	}
	resolvers := make([]string, 0, len(resolverMap))
	for r := range resolverMap {
		resolvers = append(resolvers, r)
	}
	return resolvers
}
