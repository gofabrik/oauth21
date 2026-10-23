// Package memstore is the in-memory implementation of the Store interfaces.
package memstore

import (
	"context"
	"slices"
	"sync"

	"github.com/gofabrik/oauth21/store"
)

// Store keeps every entity in memory. It is safe for concurrent use.
type Store struct {
	mu       sync.Mutex
	clients  map[string]store.Client
	requests map[string]store.AuthorizationRequest
	codes    map[string]store.Code
	tokens   map[string]store.Token
	revoked  map[string]bool
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		clients:  map[string]store.Client{},
		requests: map[string]store.AuthorizationRequest{},
		codes:    map[string]store.Code{},
		tokens:   map[string]store.Token{},
		revoked:  map[string]bool{},
	}
}

// AddClient registers c, replacing any Client with the same identifier.
func (s *Store) AddClient(c store.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = cloneClient(c)
}

// Client returns the Client with identifier id.
func (s *Store) Client(_ context.Context, id string) (store.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := get(s.clients, id)
	return cloneClient(c), err
}

// CreateAuthorizationRequest stores r.
func (s *Store) CreateAuthorizationRequest(_ context.Context, r store.AuthorizationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[r.ID] = cloneRequest(r)
	return nil
}

// AuthorizationRequest returns the Authorization Request with identifier id.
func (s *Store) AuthorizationRequest(_ context.Context, id string) (store.AuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := get(s.requests, id)
	return cloneRequest(r), err
}

// ConsumeAuthorizationRequest returns and removes the Authorization Request with identifier id.
func (s *Store) ConsumeAuthorizationRequest(_ context.Context, id string) (store.AuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := get(s.requests, id)
	delete(s.requests, id)
	return cloneRequest(r), err
}

// CreateCode stores c.
func (s *Store) CreateCode(_ context.Context, c store.Code) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[string(c.Hash)] = cloneCode(c)
	return nil
}

// Code returns the code with hash.
func (s *Store) Code(_ context.Context, hash []byte) (store.Code, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := get(s.codes, string(hash))
	return cloneCode(c), err
}

// ConsumeCode marks the code with hash used and returns it as it was before.
func (s *Store) ConsumeCode(_ context.Context, hash []byte) (store.Code, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := get(s.codes, string(hash))
	if err != nil {
		return c, err
	}
	used := c
	used.Used = true
	s.codes[string(hash)] = used
	return cloneCode(c), nil
}

// CreateToken stores t unless its Grant was revoked.
func (s *Store) CreateToken(_ context.Context, t store.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked[t.Grant.ID] {
		return store.ErrRevoked
	}
	s.tokens[string(t.Hash)] = cloneToken(t)
	return nil
}

// Token returns the token with hash.
func (s *Store) Token(_ context.Context, hash []byte) (store.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := get(s.tokens, string(hash))
	return cloneToken(t), err
}

// RevokeGrant removes every token of the Grant with identifier grantID and refuses new ones.
func (s *Store) RevokeGrant(_ context.Context, grantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[grantID] = true
	for hash, t := range s.tokens {
		if t.Grant.ID == grantID {
			delete(s.tokens, hash)
		}
	}
	return nil
}

func get[V any](m map[string]V, key string) (V, error) {
	v, ok := m[key]
	if !ok {
		return v, store.ErrNotFound
	}
	return v, nil
}

func cloneClient(c store.Client) store.Client {
	c.RedirectURIs = slices.Clone(c.RedirectURIs)
	return c
}

func cloneRequest(r store.AuthorizationRequest) store.AuthorizationRequest {
	r.Scopes = slices.Clone(r.Scopes)
	return r
}

func cloneGrant(g store.Grant) store.Grant {
	g.Scopes = slices.Clone(g.Scopes)
	g.Audience = slices.Clone(g.Audience)
	return g
}

func cloneCode(c store.Code) store.Code {
	c.Hash = slices.Clone(c.Hash)
	c.Grant = cloneGrant(c.Grant)
	return c
}

func cloneToken(t store.Token) store.Token {
	t.Hash = slices.Clone(t.Hash)
	t.Grant = cloneGrant(t.Grant)
	t.Audience = slices.Clone(t.Audience)
	return t
}
