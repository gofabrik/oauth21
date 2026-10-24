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

// ErrRequestNotPending is returned for an Authorization Request that is unknown, expired, completed or denied.
var ErrRequestNotPending = errors.New("oauth21: authorization request not pending")

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

	// AuthorizationRequestLifetime defaults to ten minutes.
	AuthorizationRequestLifetime time.Duration
	// CodeLifetime is at most ten minutes and defaults to one minute.
	CodeLifetime time.Duration
	// AccessTokenLifetime defaults to one hour.
	AccessTokenLifetime time.Duration
	// SecretHasher verifies Client secrets. It defaults to PBKDF2.
	SecretHasher SecretHasher
	// RenderError writes an authorization endpoint error that cannot be redirected to the Client. It defaults to a plain text response.
	RenderError func(w http.ResponseWriter, r *http.Request, e AuthorizationError)
	// Clock defaults to time.Now. Stores that remove expired entities must use the same clock, such as memstore.NewWithClock(Clock).
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
	if !validLifetime(c.AuthorizationRequestLifetime) || !validLifetime(c.CodeLifetime) || c.CodeLifetime > 10*time.Minute || !validLifetime(c.AccessTokenLifetime) {
		return nil, errors.New("oauth21: lifetimes must be at least one second, and CodeLifetime at most ten minutes")
	}
	if c.AuthorizationRequestLifetime == 0 {
		c.AuthorizationRequestLifetime = 10 * time.Minute
	}
	if c.CodeLifetime == 0 {
		c.CodeLifetime = time.Minute
	}
	if c.AccessTokenLifetime == 0 {
		c.AccessTokenLifetime = time.Hour
	}
	if c.SecretHasher == nil {
		c.SecretHasher = PBKDF2{}
	}
	if c.RenderError == nil {
		c.RenderError = renderError
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

// AuthorizationError is an authorization endpoint error found before the Client and its redirect URI are trusted.
type AuthorizationError struct {
	Status      int
	Code        string
	Description string
}

func renderError(w http.ResponseWriter, _ *http.Request, e AuthorizationError) {
	http.Error(w, (&wire.Error{Code: e.Code, Description: e.Description}).Error(), e.Status)
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
	r, err := s.pendingRequest(ctx, id, s.config.AuthorizationRequests.AuthorizationRequest)
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
	r, err := s.pendingRequest(ctx, id, s.config.AuthorizationRequests.AuthorizationRequest)
	if err != nil {
		return "", err
	}
	code, perr := protocol.IssueCode(protocolRequest(r), c.Subject, c.Scopes, s.config.Clock().Add(s.config.CodeLifetime), s.config.AccessTokenLifetime)
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
	if _, err := s.pendingRequest(ctx, id, s.config.AuthorizationRequests.ConsumeAuthorizationRequest); err != nil {
		return "", err
	}
	if err := s.config.Codes.CreateCode(ctx, storeCode(valueHash, grantID, code)); err != nil {
		return "", err
	}
	return s.authorizationResponse(r.RedirectURI, r.State).Code(value)
}

// Deny denies the Authorization Request with identifier id and returns the redirect for the Resource Owner.
func (s *Server) Deny(ctx context.Context, id string) (string, error) {
	r, err := s.pendingRequest(ctx, id, s.config.AuthorizationRequests.ConsumeAuthorizationRequest)
	if err != nil {
		return "", err
	}
	return s.authorizationResponse(r.RedirectURI, r.State).Error(oauthError(protocol.Denied()))
}

// pendingRequest loads the Authorization Request id with load and applies protocol's lifecycle decision on it.
func (s *Server) pendingRequest(ctx context.Context, id string, load func(context.Context, string) (store.AuthorizationRequest, error)) (store.AuthorizationRequest, error) {
	stored, err := load(ctx, id)
	var a *protocol.AuthorizationRequest
	switch {
	case err == nil:
		r := protocolRequest(stored)
		a = &r
	case !errors.Is(err, store.ErrNotFound):
		return store.AuthorizationRequest{}, err
	}
	if perr := protocol.Pending(a, s.config.Clock()); perr != nil {
		return store.AuthorizationRequest{}, fmt.Errorf("%w: %s", ErrRequestNotPending, perr.Description)
	}
	return stored, nil
}

// AuthorizationHandler returns the authorization endpoint.
func (s *Server) AuthorizationHandler() http.Handler {
	return http.HandlerFunc(s.authorize)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	loc, err := s.authorizationRedirect(r)
	if err != nil {
		e := responseError(err)
		s.config.RenderError(w, r, AuthorizationError{Status: e.Status(), Code: e.Code, Description: e.Description})
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
	a, perr := protocol.Authorize(client, protocol.AuthorizationParams(params), s.config.Clock().Add(s.config.AuthorizationRequestLifetime))
	switch {
	case a.RedirectURI == "" && perr != nil:
		return "", oauthError(perr)
	case a.RedirectURI == "":
		return "", errors.New("oauth21: authorization request has no redirect URI")
	}
	resp := s.authorizationResponse(a.RedirectURI, a.State)
	if perr != nil {
		return resp.Error(oauthError(perr))
	}
	loc, err := s.handOff(r.Context(), a)
	if err != nil {
		return resp.Error(responseError(err))
	}
	return loc, nil
}

// authorizationResponse returns the authorization response to redirectURI carrying state and the issuer.
func (s *Server) authorizationResponse(redirectURI, state string) wire.AuthorizationResponse {
	return wire.AuthorizationResponse{RedirectURI: redirectURI, State: state, Issuer: s.config.Issuer}
}

// handOff stores a and returns the redirect to the login URL.
func (s *Server) handOff(ctx context.Context, a protocol.AuthorizationRequest) (string, error) {
	id, err := s.random()
	if err != nil {
		return "", err
	}
	if err := s.config.AuthorizationRequests.CreateAuthorizationRequest(ctx, storeRequest(id, a)); err != nil {
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
	clientID, perr := protocol.Identify(req)
	if perr != nil {
		return wire.TokenResponse{}, oauthError(perr)
	}
	client, err := s.client(r.Context(), clientID)
	if err != nil {
		return wire.TokenResponse{}, err
	}
	if perr := protocol.ValidateTokenRequest(client, req, s.config.SecretHasher.Verify); perr != nil {
		return wire.TokenResponse{}, oauthError(perr)
	}
	stored, now, err := s.redeemCode(r.Context(), clientID, req)
	if err != nil {
		return wire.TokenResponse{}, err
	}
	value, valueHash, err := s.secret()
	if err != nil {
		return wire.TokenResponse{}, err
	}
	expiresAt := protocol.AccessTokenExpiry(protocolCode(stored), now, s.config.AccessTokenLifetime)
	err = s.config.Tokens.CreateToken(r.Context(), store.Token{
		Hash:      valueHash,
		Grant:     stored.Grant,
		Audience:  stored.Grant.Audience,
		ExpiresAt: expiresAt,
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
		ExpiresIn:   int64(expiresAt.Sub(now) / time.Second),
		Scope:       strings.Join(stored.Grant.Scopes, " "),
	}, nil
}

// redeemCode applies protocol's two-step redemption decision to the code of req from the Client clientID, and returns the time it was redeemed at.
func (s *Server) redeemCode(ctx context.Context, clientID string, req protocol.TokenRequest) (store.Code, time.Time, error) {
	stored, code, err := loadCode(ctx, req.Code, s.config.Codes.Code)
	if err != nil {
		return store.Code{}, time.Time{}, err
	}
	now := s.config.Clock()
	effect, perr := protocol.Redeem(code, clientID, req, now)
	if effect == protocol.ConsumeCode {
		if stored, code, err = loadCode(ctx, req.Code, s.config.Codes.ConsumeCode); err != nil {
			return store.Code{}, time.Time{}, err
		}
		now = s.config.Clock()
		effect, perr = protocol.Consumed(code, now)
	}
	if effect == protocol.RevokeGrant {
		if err := s.config.Tokens.RevokeGrant(ctx, stored.Grant.ID); err != nil {
			return store.Code{}, time.Time{}, err
		}
	}
	if perr != nil {
		return store.Code{}, time.Time{}, oauthError(perr)
	}
	return stored, now, nil
}

// loadCode loads the code with the given value with load, as stored and as protocol sees it, nil when unknown.
func loadCode(ctx context.Context, value string, load func(context.Context, []byte) (store.Code, error)) (store.Code, *protocol.Code, error) {
	stored, err := load(ctx, hash(value))
	if errors.Is(err, store.ErrNotFound) {
		return store.Code{}, nil, nil
	}
	if err != nil {
		return store.Code{}, nil, err
	}
	c := protocolCode(stored)
	return stored, &c, nil
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
	return protocol.Client{ID: c.ID, Public: c.Type == store.Public, RedirectURIs: c.RedirectURIs, SecretHash: c.SecretHash}
}

func protocolRequest(r store.AuthorizationRequest) protocol.AuthorizationRequest {
	return protocol.AuthorizationRequest{
		ClientID:            r.ClientID,
		RedirectURI:         r.RedirectURI,
		State:               r.State,
		Scopes:              r.Scopes,
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
		ExpiresAt:           r.ExpiresAt,
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
		ExpiresAt:           a.ExpiresAt,
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
		RetainUntil:         c.RetainUntil,
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
		RetainUntil:         c.RetainUntil,
	}
}
