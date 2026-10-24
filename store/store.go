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
	// AllowedScopes are the scopes the Client may request.
	AllowedScopes []string
	// DefaultScopes are requested for the Client when it omits scope.
	DefaultScopes []string
	// GrantTypes are the grant types the Client may use, authorization_code and refresh_token when empty.
	GrantTypes []string
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

// Grant is the authorization a Client holds, given by a Resource Owner or obtained for itself with client credentials.
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
	Hash  []byte
	Grant Grant
	// Scopes are the scopes of the token, the Grant's or fewer.
	Scopes    []string
	Audience  []string
	ExpiresAt time.Time
}

// RefreshToken is a refresh token, stored by the SHA-256 hash of its value.
type RefreshToken struct {
	Hash      []byte
	Grant     Grant
	ExpiresAt time.Time
	// Rotated is set once the refresh token was replaced by a new one.
	Rotated bool
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

// Tokens holds the access tokens and the refresh tokens, rotated or not, until they expire.
type Tokens interface {
	// CreateToken fails with ErrRevoked when the Grant of t was revoked.
	CreateToken(ctx context.Context, t Token) error
	Token(ctx context.Context, hash []byte) (Token, error)
	// RevokeToken removes the access token with hash, if there is one.
	RevokeToken(ctx context.Context, hash []byte) error
	// CreateRefreshToken fails with ErrRevoked when the Grant of t was revoked.
	CreateRefreshToken(ctx context.Context, t RefreshToken) error
	RefreshToken(ctx context.Context, hash []byte) (RefreshToken, error)
	// RotateRefreshToken atomically marks a refresh token rotated and returns it as it was before; it stores next only when the token was not rotated yet and its Grant was not revoked.
	RotateRefreshToken(ctx context.Context, hash []byte, next RefreshToken) (RefreshToken, error)
	// RevokeGrant removes every access and refresh token of the Grant with identifier grantID and refuses new ones.
	RevokeGrant(ctx context.Context, grantID string) error
}
