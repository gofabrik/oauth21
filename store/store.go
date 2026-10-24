// Package store defines the persisted entities and the Store interfaces that hold them.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a Store has no entity with the given key.
var ErrNotFound = errors.New("store: not found")

// ErrRevoked is returned when a token is created for a revoked Grant.
var ErrRevoked = errors.New("store: grant revoked")

// ClientType is whether a Client can keep a secret.
type ClientType int

const (
	Confidential ClientType = iota + 1
	Public
)

// Client is an application registered with the Authorization Server.
type Client struct {
	ID           string
	Type         ClientType
	RedirectURIs []string
	// SecretHash is the SecretHasher hash of a confidential Client's secret.
	SecretHash string
}

// AuthorizationRequest is a validated request waiting for the Host Application.
type AuthorizationRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	State               string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	// ExpiresAt must be stored; a zero value counts as expired.
	ExpiresAt time.Time
}

// Grant is the authorization a Resource Owner gave a Client.
type Grant struct {
	ID       string
	ClientID string
	Subject  string
	Scopes   []string
	Audience []string
}

// Code is an authorization code, stored by the SHA-256 hash of its value.
type Code struct {
	Hash                []byte
	Grant               Grant
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	// RetainUntil is when the Store may remove the code, used or not.
	RetainUntil time.Time
	Used        bool
}

// Token is an access token, stored by the SHA-256 hash of its value.
type Token struct {
	Hash      []byte
	Grant     Grant
	Audience  []string
	ExpiresAt time.Time
}

// Clients holds the registered Clients.
type Clients interface {
	Client(ctx context.Context, id string) (Client, error)
}

// AuthorizationRequests holds the Authorization Requests until they are consumed; it may remove expired ones.
type AuthorizationRequests interface {
	CreateAuthorizationRequest(ctx context.Context, r AuthorizationRequest) error
	AuthorizationRequest(ctx context.Context, id string) (AuthorizationRequest, error)
	// ConsumeAuthorizationRequest atomically returns and removes an Authorization Request.
	ConsumeAuthorizationRequest(ctx context.Context, id string) (AuthorizationRequest, error)
}

// Codes holds the authorization codes until their RetainUntil.
type Codes interface {
	CreateCode(ctx context.Context, c Code) error
	Code(ctx context.Context, hash []byte) (Code, error)
	// ConsumeCode atomically marks a code used and returns it as it was before.
	ConsumeCode(ctx context.Context, hash []byte) (Code, error)
}

// Tokens holds the access tokens.
type Tokens interface {
	// CreateToken fails with ErrRevoked when the Grant of t was revoked.
	CreateToken(ctx context.Context, t Token) error
	Token(ctx context.Context, hash []byte) (Token, error)
	// RevokeGrant removes every token of the Grant with identifier grantID and refuses new ones.
	RevokeGrant(ctx context.Context, grantID string) error
}
