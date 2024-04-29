package store

// Store is a storage for ip based wildcard removal
type Store struct {
	IP map[string]*IPMeta
}

// IPMeta contains meta-information about a single
// IP address found during enumeration.
type IPMeta struct {
	// we store also the ip itself as we will need it later for filtering
	IP string
	// Hostnames contains the list of hostnames for the IP
	Hostnames map[string]struct{}
	// Counter is the number of times the same ip was found for hosts
	Counter int
}

// New creates a new storage for ip based wildcard removal
func New() *Store {
	return &Store{
		IP: make(map[string]*IPMeta),
	}
}

// New creates a new ip-hostname pair in the map
func (s *Store) New(ip, hostname string) {
	hostnames := make(map[string]struct{})
	hostnames[hostname] = struct{}{}
	s.IP[ip] = &IPMeta{IP: ip, Hostnames: hostnames, Counter: 1}
}

// Exists indicates if an IP exists in the map
func (s *Store) Exists(ip string) bool {
	_, ok := s.IP[ip]
	return ok
}

// Get gets the meta-information for an IP address from the map.
func (s *Store) Get(ip string) *IPMeta {
	return s.IP[ip]
}

// Delete deletes the records for an IP from store.
func (s *Store) Delete(ip string) {
	delete(s.IP, ip)
}

// Close removes all the references to arrays and releases memory to the gc
func (s *Store) Close() {
	for ip := range s.IP {
		s.IP[ip].Hostnames = nil
	}
}
