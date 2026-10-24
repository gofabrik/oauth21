// Package bearer protects the routes of a Resource Server with Bearer access tokens (RFC 6750).
package bearer

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gofabrik/oauth21/internal/protocol"
	"github.com/gofabrik/oauth21/internal/wire"
	"github.com/gofabrik/oauth21/store"
)

// ErrInvalidToken is returned by a Validator for an access token that is not active.
var ErrInvalidToken = errors.New("bearer: invalid token")

// Token is a validated access token.
type Token struct {
	Subject  string
	ClientID string
	Scopes   []string
	Audience []string
}

// Validator validates access tokens.
type Validator interface {
	// Validate returns the access token with value token, failing with ErrInvalidToken when it is not active.
	Validate(ctx context.Context, token string) (Token, error)
}

// Local validates access tokens against the token Store of an Authorization Server in the same process.
type Local struct {
	Tokens store.Tokens
	// ClientID is the Client identifier of the Resource Server, which an access token with an audience must contain.
	ClientID string
	// Clock defaults to time.Now.
	Clock func() time.Time
}

// Validate returns the access token with value token while it is active for the Resource Server.
func (l Local) Validate(ctx context.Context, token string) (Token, error) {
	sum := sha256.Sum256([]byte(token))
	t, err := l.Tokens.Token(ctx, sum[:])
	if errors.Is(err, store.ErrNotFound) {
		return Token{}, ErrInvalidToken
	}
	if err != nil {
		return Token{}, err
	}
	now := time.Now
	if l.Clock != nil {
		now = l.Clock
	}
	p := protocol.Token{ClientID: t.Grant.ClientID, Subject: t.Grant.Subject, Scopes: t.Scopes, Audience: t.Audience, ExpiresAt: t.ExpiresAt}
	if protocol.Introspect(&p, l.ClientID, now()) == nil {
		return Token{}, ErrInvalidToken
	}
	return Token{Subject: p.Subject, ClientID: p.ClientID, Scopes: p.Scopes, Audience: p.Audience}, nil
}

type contextKey struct{}

// FromContext returns the access token the middleware validated for the request with ctx.
func FromContext(ctx context.Context) (Token, bool) {
	t, ok := ctx.Value(contextKey{}).(Token)
	return t, ok
}

// Middleware returns a middleware that passes on only requests whose Authorization header carries an access token that v validates and that has every scope in required, which must be scope-tokens.
func Middleware(v Validator, required ...string) func(http.Handler) http.Handler {
	if slices.ContainsFunc(required, func(s string) bool { return !protocol.ScopeToken(s) }) {
		panic("bearer: scopes must be scope-tokens")
	}
	required = slices.Clone(required)
	scope := strings.Join(required, " ")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			value, werr := wire.ParseBearer(r)
			switch {
			case werr != nil:
				wire.WriteBearerError(w, werr, scope)
				return
			case value == "":
				wire.WriteBearerError(w, nil, scope)
				return
			}
			token, err := v.Validate(r.Context(), value)
			if err != nil && !errors.Is(err, ErrInvalidToken) {
				wire.WriteBearerError(w, &wire.Error{Code: wire.ServerError}, scope)
				return
			}
			if perr := protocol.Access(err == nil, token.Scopes, required); perr != nil {
				wire.WriteBearerError(w, (*wire.Error)(perr), scope)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, token)))
		})
	}
}
