package store

import (
	"fmt"
	"sync"

	"github.com/Alexmaster12345/netforge-api/internal/models"
)

// Store is a thread-safe in-memory registry of firewall rules and blacklist entries.
// It mirrors desired state; the NFT service keeps the kernel in sync.
type Store struct {
	mu        sync.RWMutex
	rules     map[string]*models.Rule
	blacklist map[string]*models.BlacklistEntry // keyed by IP
}

func New() *Store {
	return &Store{
		rules:     make(map[string]*models.Rule),
		blacklist: make(map[string]*models.BlacklistEntry),
	}
}

// Rules -----------------------------------------------------------------------

func (s *Store) AddRule(r *models.Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[r.ID] = r
}

func (s *Store) GetRule(id string) (*models.Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[id]
	return r, ok
}

func (s *Store) DeleteRule(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.rules[id]
	if ok {
		delete(s.rules, id)
	}
	return ok
}

func (s *Store) ListRules() []*models.Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.Rule, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r)
	}
	return out
}

// Blacklist -------------------------------------------------------------------

func (s *Store) AddBlacklist(entry *models.BlacklistEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.blacklist[entry.IP]; exists {
		return fmt.Errorf("ip %s is already blacklisted", entry.IP)
	}
	s.blacklist[entry.IP] = entry
	return nil
}

func (s *Store) GetBlacklist(ip string) (*models.BlacklistEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.blacklist[ip]
	return e, ok
}

func (s *Store) DeleteBlacklist(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.blacklist[ip]
	if ok {
		delete(s.blacklist, ip)
	}
	return ok
}

func (s *Store) ListBlacklist() []*models.BlacklistEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.BlacklistEntry, 0, len(s.blacklist))
	for _, e := range s.blacklist {
		out = append(out, e)
	}
	return out
}
