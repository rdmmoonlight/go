package store

import (
	"context"
	"strings"
	"sync"
)

// MemoryStore adalah implementasi dalam memori untuk tes unit.
// Jangan dipakai di cmd/server: data hilang saat restart.
type MemoryStore struct {
	mu      sync.RWMutex
	byEmail map[string]*User
}

func NewMemory() *MemoryStore {
	return &MemoryStore{byEmail: make(map[string]*User)}
}

func (s *MemoryStore) Create(_ context.Context, name, email, passwordHash string) (*User, error) {
	key := normalize(email)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byEmail[key]; ok {
		return nil, ErrEmailTaken
	}
	u := &User{ID: newID(), Name: name, Email: key, PasswordHash: passwordHash}
	s.byEmail[key] = u
	return u, nil
}

func (s *MemoryStore) FindByEmail(_ context.Context, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byEmail[normalize(email)]
	if !ok {
		return nil, ErrNotFound
	}
	return u, nil
}

func (s *MemoryStore) UpsertExternal(_ context.Context, name, email string) (*User, error) {
	key := normalize(email)
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.byEmail[key]; ok {
		return u, nil
	}
	u := &User{ID: newID(), Name: name, Email: key}
	s.byEmail[key] = u
	return u, nil
}

func (s *MemoryStore) byID(id string) *User {
	for _, u := range s.byEmail {
		if u.ID == id {
			return u
		}
	}
	return nil
}

func (s *MemoryStore) FindByID(_ context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u := s.byID(id)
	if u == nil {
		return nil, ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *MemoryStore) UpdateProfile(_ context.Context, id string, upd ProfileUpdate) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.byID(id)
	if u == nil {
		return nil, ErrNotFound
	}
	if upd.UserName != nil {
		for _, other := range s.byEmail {
			if other.ID != id && other.UserName != "" && strings.EqualFold(other.UserName, *upd.UserName) {
				return nil, ErrUserNameTaken
			}
		}
		u.UserName = *upd.UserName
	}
	if upd.Name != nil {
		u.Name = *upd.Name
	}
	if upd.AvatarURL != nil {
		u.AvatarURL = *upd.AvatarURL
	}
	u.PhoneNumber = upd.PhoneNumber
	u.Bio = upd.Bio
	cp := *u
	return &cp, nil
}

func (s *MemoryStore) UpdatePasswordHash(_ context.Context, id, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.byID(id)
	if u == nil {
		return ErrNotFound
	}
	u.PasswordHash = passwordHash
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.byID(id)
	if u == nil {
		return ErrNotFound
	}
	delete(s.byEmail, u.Email)
	return nil
}
