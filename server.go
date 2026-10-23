package oauth21

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofabrik/oauth21/internal/protocol"
	"github.com/gofabrik/oauth21/internal/wire"
	"github.com/gofabrik/oauth21/store"
)

// ErrInvalidCompletion is returned by Complete for a Completion the server rejects.
var ErrInvalidCompletion = errors.New("oauth21: invalid completion")

// Config configures an Authorization Server.
type Config struct {
	// Issuer is the issuer identifier: an https URL without query or fragment.
	Issuer string
	// LoginURL is the Host Application's login page, which receives a request_id parameter.
	LoginURL string

	Clients               store.Clients
	AuthorizationRequests store.AuthorizationRequests
	Codes                 store.Codes
	Tokens                store.Tokens

	// CodeLifetime is at most ten minutes and defaults to one minute.
	CodeLifetime time.Duration
	// AccessTokenLifetime defaults to one hour.
	AccessTokenLifetime time.Duration
	// Clock defaults to time.Now.
	Clock func() time.Time
	// Random defaults to crypto/rand.Reader.
	Random io.Reader
}

// Server is an Authorization Server.
type Server struct {
	config Config
}

// New returns an Authorization Server built from c.
func New(c Config) (*Server, error) {
	if u, err := url.Parse(c.Issuer); err != nil || u.Scheme != "https" || u.Host == "" || strings.ContainsAny(c.Issuer, "?#") {
		return nil, errors.New("oauth21: Issuer must be an https URL without query or fragment")
	}
	if _, err := url.Parse(c.LoginURL); c.LoginURL == "" || err != nil {
		return nil, errors.New("oauth21: LoginURL must be a URL")
	}
	if c.Clients == nil || c.AuthorizationRequests == nil || c.Codes == nil || c.Tokens == nil {
		return nil, errors.New("oauth21: every Store is required")
	}
	if !validLifetime(c.CodeLifetime) || c.CodeLifetime > 10*time.Minute || !validLifetime(c.AccessTokenLifetime) {
		return nil, errors.New("oauth21: lifetimes must be at least one second, and CodeLifetime at most ten minutes")
	}
	if c.CodeLifetime == 0 {
		c.CodeLifetime = time.Minute
	}
	if c.AccessTokenLifetime == 0 {
		c.AccessTokenLifetime = time.Hour
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.Random == nil {
		c.Random = rand.Reader
	}
	return &Server{c}, nil
}

// validLifetime reports whether d is unset or at least one second.
func validLifetime(d time.Duration) bool {
	return d == 0 || d >= time.Second
}

// AuthorizationRequest is a pending Authorization Request as the Host Application sees it.
type AuthorizationRequest struct {
	ID     string
	Client store.Client
	Scopes []string
}

// Completion is the Host Application's answer to an Authorization Request.
type Completion struct {
	// Subject identifies the Resource Owner.
	Subject string
	Scopes  []string
}

// AuthorizationRequest returns the pending Authorization Request with identifier id.
func (s *Server) AuthorizationRequest(ctx context.Context, id string) (AuthorizationRequest, error) {
	r, err := s.config.AuthorizationRequests.AuthorizationRequest(ctx, id)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	client, err := s.config.Clients.Client(ctx, r.ClientID)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	return AuthorizationRequest{ID: r.ID, Client: client, Scopes: r.Scopes}, nil
}

// Complete completes the Authorization Request with identifier id and returns the redirect for the Resource Owner.
func (s *Server) Complete(ctx context.Context, id string, c Completion) (string, error) {
	r, err := s.config.AuthorizationRequests.AuthorizationRequest(ctx, id)
	if err != nil {
		return "", err
	}
	code, perr := protocol.IssueCode(protocolRequest(r), c.Subject, c.Scopes, s.config.Clock().Add(s.config.CodeLifetime))
	if perr != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidCompletion, perr.Description)
	}
	value, valueHash, err := s.secret()
	if err != nil {
		return "", err
	}
	grantID, err := s.random()
	if err != nil {
		return "", err
	}
	if _, err := s.config.AuthorizationRequests.ConsumeAuthorizationRequest(ctx, id); err != nil {
		return "", err
	}
	if err := s.config.Codes.CreateCode(ctx, storeCode(valueHash, grantID, code)); err != nil {
		return "", err
	}
	return wire.AuthorizationResponse{RedirectURI: r.RedirectURI, State: r.State, Issuer: s.config.Issuer}.Code(value)
}

// AuthorizationHandler returns the authorization endpoint.
func (s *Server) AuthorizationHandler() http.Handler {
	return http.HandlerFunc(s.authorize)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	loc, err := s.authorizationRedirect(r)
	if err != nil {
		e := responseError(err)
		http.Error(w, e.Error(), e.Status())
		return
	}
	http.Redirect(w, r, loc, http.StatusFound) // #nosec G710 -- loc is the login URL or a registered redirect URI
}

// authorizationRedirect stores the Authorization Request of r and returns the redirect to the login URL or the Client.
func (s *Server) authorizationRedirect(r *http.Request) (string, error) {
	params, werr := wire.ParseAuthorizationParams(r)
	if werr != nil {
		return "", werr
	}
	client, err := s.client(r.Context(), params.ClientID)
	if err != nil {
		return "", err
	}
	a, perr := protocol.Authorize(client, protocol.AuthorizationParams(params))
	if perr != nil {
		if a.RedirectURI == "" {
			return "", oauthError(perr)
		}
		return wire.AuthorizationResponse{RedirectURI: a.RedirectURI, State: a.State, Issuer: s.config.Issuer}.Error(oauthError(perr))
	}
	id, err := s.random()
	if err != nil {
		return "", err
	}
	if err := s.config.AuthorizationRequests.CreateAuthorizationRequest(r.Context(), storeRequest(id, a)); err != nil {
		return "", err
	}
	return wire.Redirect(s.config.LoginURL, url.Values{"request_id": {id}})
}

// TokenHandler returns the token endpoint.
func (s *Server) TokenHandler() http.Handler {
	return http.HandlerFunc(s.token)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	resp, err := s.redeem(r)
	if err != nil {
		wire.WriteTokenError(w, responseError(err), wire.Challenge(r))
		return
	}
	wire.WriteToken(w, resp)
}

// redeem redeems the code of the token request r for an access token.
func (s *Server) redeem(r *http.Request) (wire.TokenResponse, error) {
	parsed, werr := wire.ParseTokenRequest(r)
	if werr != nil {
		return wire.TokenResponse{}, werr
	}
	req := protocol.TokenRequest(parsed)
	client, err := s.client(r.Context(), req.ClientID)
	if err != nil {
		return wire.TokenResponse{}, err
	}
	if perr := protocol.ValidateTokenRequest(client, req); perr != nil {
		return wire.TokenResponse{}, oauthError(perr)
	}
	if _, err := s.redeemCode(r.Context(), req, s.config.Codes.Code); err != nil {
		return wire.TokenResponse{}, err
	}
	stored, err := s.redeemCode(r.Context(), req, s.config.Codes.ConsumeCode)
	if err != nil {
		return wire.TokenResponse{}, err
	}
	value, valueHash, err := s.secret()
	if err != nil {
		return wire.TokenResponse{}, err
	}
	err = s.config.Tokens.CreateToken(r.Context(), store.Token{
		Hash:      valueHash,
		Grant:     stored.Grant,
		Audience:  stored.Grant.Audience,
		ExpiresAt: s.config.Clock().Add(s.config.AccessTokenLifetime),
	})
	if perr := protocol.TokenCreated(errors.Is(err, store.ErrRevoked)); perr != nil {
		return wire.TokenResponse{}, oauthError(perr)
	}
	if err != nil {
		return wire.TokenResponse{}, err
	}
	return wire.TokenResponse{
		AccessToken: value,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.config.AccessTokenLifetime / time.Second),
		Scope:       strings.Join(stored.Grant.Scopes, " "),
	}, nil
}

// redeemCode loads the code of req with load and applies protocol's redemption decision on it.
func (s *Server) redeemCode(ctx context.Context, req protocol.TokenRequest, load func(context.Context, []byte) (store.Code, error)) (store.Code, error) {
	stored, err := load(ctx, hash(req.Code))
	var code *protocol.Code
	switch {
	case err == nil:
		c := protocolCode(stored)
		code = &c
	case !errors.Is(err, store.ErrNotFound):
		return store.Code{}, err
	}
	revoke, perr := protocol.Redeem(code, req, s.config.Clock())
	if revoke {
		if err := s.config.Tokens.RevokeGrant(ctx, stored.Grant.ID); err != nil {
			return store.Code{}, err
		}
	}
	if perr != nil {
		return store.Code{}, oauthError(perr)
	}
	return stored, nil
}

// client loads the Client with identifier id, or nil when there is none.
func (s *Server) client(ctx context.Context, id string) (*protocol.Client, error) {
	c, err := s.config.Clients.Client(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	client := protocolClient(c)
	return &client, nil
}

// random returns a fresh opaque value with 256 bits of entropy.
func (s *Server) random() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(s.config.Random, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// secret returns a fresh opaque value and the hash the Stores receive instead.
func (s *Server) secret() (string, []byte, error) {
	v, err := s.random()
	if err != nil {
		return "", nil, err
	}
	return v, hash(v), nil
}

func hash(v string) []byte {
	sum := sha256.Sum256([]byte(v))
	return sum[:]
}

// responseError returns the error response for err, server_error unless it is an OAuth error.
func responseError(err error) *wire.Error {
	var e *wire.Error
	if errors.As(err, &e) {
		return e
	}
	return &wire.Error{Code: wire.ServerError}
}

// oauthError converts a protocol error into its error response.
func oauthError(e *protocol.Error) *wire.Error {
	return (*wire.Error)(e)
}

func protocolClient(c store.Client) protocol.Client {
	return protocol.Client{ID: c.ID, Public: c.Type == store.Public, RedirectURIs: c.RedirectURIs}
}

func protocolRequest(r store.AuthorizationRequest) protocol.AuthorizationRequest {
	return protocol.AuthorizationRequest{
		ClientID:            r.ClientID,
		RedirectURI:         r.RedirectURI,
		State:               r.State,
		Scopes:              r.Scopes,
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
	}
}

func storeRequest(id string, a protocol.AuthorizationRequest) store.AuthorizationRequest {
	return store.AuthorizationRequest{
		ID:                  id,
		ClientID:            a.ClientID,
		RedirectURI:         a.RedirectURI,
		State:               a.State,
		Scopes:              a.Scopes,
		CodeChallenge:       a.CodeChallenge,
		CodeChallengeMethod: a.CodeChallengeMethod,
	}
}

func protocolCode(c store.Code) protocol.Code {
	return protocol.Code{
		ClientID:            c.Grant.ClientID,
		Subject:             c.Grant.Subject,
		Scopes:              c.Grant.Scopes,
		RedirectURI:         c.RedirectURI,
		CodeChallenge:       c.CodeChallenge,
		CodeChallengeMethod: c.CodeChallengeMethod,
		ExpiresAt:           c.ExpiresAt,
		Used:                c.Used,
	}
}

func storeCode(hash []byte, grantID string, c protocol.Code) store.Code {
	return store.Code{
		Hash:                hash,
		Grant:               store.Grant{ID: grantID, ClientID: c.ClientID, Subject: c.Subject, Scopes: c.Scopes},
		RedirectURI:         c.RedirectURI,
		CodeChallenge:       c.CodeChallenge,
		CodeChallengeMethod: c.CodeChallengeMethod,
		ExpiresAt:           c.ExpiresAt,
	}
}
