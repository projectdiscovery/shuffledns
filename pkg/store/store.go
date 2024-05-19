package store

import (
	"os"
	"strings"

	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const Megabyte = 1 << 20

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
		CompactionTableSize: 256 * Megabyte,
	})
	if err != nil {
		return nil, err
	}
	return &Store{DB: db}, nil
}

// New creates a new ip-hostname pair in the map
func (s *Store) New(ip, hostname string) error {
	return s.DB.Put([]byte(ip), []byte(hostname), nil)
}

// Exists indicates if an IP exists in the map
func (s *Store) Exists(ip string) bool {
	ok, err := s.DB.Has([]byte(ip), nil)
	return err == nil && ok
}

// Get gets the meta-information for an IP address from the map.
func (s *Store) GetHostnames(ip string) string {
	hostname, err := s.DB.Get([]byte(ip), nil)
	if err != nil {
		return ""
	}
	return string(hostname)
}

func (s *Store) Update(ip, hostname string) error {
	hostnames, err := s.DB.Get([]byte(ip), nil)
	if err != nil {
		return err
	}
	return s.DB.Put([]byte(ip), []byte(string(hostnames)+","+hostname), nil)
}

// Delete deletes the records for an IP from store.
func (s *Store) Delete(ip string) error {
	return s.DB.Delete([]byte(ip), nil)
}

func (s *Store) Close() {
	s.DB.Close()
}

func (s *Store) Iterate(f func(ip string, hostnames []string, counter int)) {
	iter := s.DB.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		ip := string(iter.Key())
		hostnames := strings.Split(string(iter.Value()), ",")
		hostnames = sliceutil.Dedupe(hostnames)
		counter := len(hostnames)
		f(ip, hostnames, counter)
	}
}
