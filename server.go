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
	"slices"
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

	// Scopes are the supported scopes, at least one, each a scope-token.
	Scopes []string
	// AuthorizationRequestLifetime defaults to ten minutes.
	AuthorizationRequestLifetime time.Duration
	// CodeLifetime is at most ten minutes and defaults to one minute.
	CodeLifetime time.Duration
	// AccessTokenLifetime defaults to one hour.
	AccessTokenLifetime time.Duration
	// RefreshTokenLifetime is the lifetime of a Refresh Token Family, which no access token outlives. It defaults to 30 days.
	RefreshTokenLifetime time.Duration
	// ReuseConfidentialRefreshTokens stops the rotation of confidential Clients' refresh tokens.
	ReuseConfidentialRefreshTokens bool
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
	if len(c.Scopes) == 0 || slices.ContainsFunc(c.Scopes, func(s string) bool { return !protocol.ScopeToken(s) }) {
		return nil, errors.New("oauth21: Scopes must be one or more scope-tokens")
	}
	if !validLifetime(c.AuthorizationRequestLifetime) || !validLifetime(c.CodeLifetime) || c.CodeLifetime > 10*time.Minute || !validLifetime(c.AccessTokenLifetime) || !validLifetime(c.RefreshTokenLifetime) {
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
	if c.RefreshTokenLifetime == 0 {
		c.RefreshTokenLifetime = 30 * 24 * time.Hour
	}
	c.Scopes = slices.Clone(c.Scopes)
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
	code, perr := protocol.IssueCode(protocolRequest(r), c.Subject, c.Scopes, s.config.Clock().Add(s.config.CodeLifetime), max(s.config.AccessTokenLifetime, s.config.RefreshTokenLifetime))
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
	a, perr := protocol.Authorize(client, protocol.AuthorizationParams(params), s.config.Scopes, s.config.Clock().Add(s.config.AuthorizationRequestLifetime))
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
	resp, err := s.tokenResponse(r)
	if err != nil {
		wire.WriteError(w, responseError(err), wire.Challenge(r))
		return
	}
	wire.WriteToken(w, resp)
}

// tokenResponse answers the token request r.
func (s *Server) tokenResponse(r *http.Request) (wire.TokenResponse, error) {
	parsed, credentials, werr := wire.ParseTokenRequest(r)
	if werr != nil {
		return wire.TokenResponse{}, werr
	}
	req, c := protocol.TokenRequest(parsed), protocol.Credentials(credentials)
	client, err := s.identify(r.Context(), c)
	if err != nil {
		return wire.TokenResponse{}, err
	}
	if perr := protocol.ValidateTokenRequest(client, req, c, s.config.SecretHasher.Verify); perr != nil {
		return wire.TokenResponse{}, oauthError(perr)
	}
	switch req.GrantType {
	case protocol.RefreshTokenGrant:
		return s.refresh(r.Context(), *client, req)
	case protocol.ClientCredentialsGrant:
		return s.clientCredentials(r.Context(), *client, req)
	}
	return s.redeem(r.Context(), *client, req)
}

// redeem redeems the code of req from client for an access token, and a refresh token when protocol issues one.
func (s *Server) redeem(ctx context.Context, client protocol.Client, req protocol.TokenRequest) (wire.TokenResponse, error) {
	stored, now, err := s.redeemCode(ctx, client.ID, req)
	if err != nil {
		return wire.TokenResponse{}, err
	}
	token := protocol.IssueRefreshToken(client, protocolCode(stored), now, s.config.RefreshTokenLifetime)
	if token == nil {
		return s.issueToken(ctx, stored.Grant, stored.Grant.Scopes, now, stored.RetainUntil)
	}
	value, valueHash, err := s.secret()
	if err != nil {
		return wire.TokenResponse{}, err
	}
	refresh := storeRefreshToken(valueHash, stored.Grant, *token)
	if err := creationError(s.config.Tokens.CreateRefreshToken(ctx, refresh)); err != nil {
		return wire.TokenResponse{}, err
	}
	resp, err := s.issueToken(ctx, stored.Grant, stored.Grant.Scopes, now, refresh.ExpiresAt)
	if err != nil {
		return wire.TokenResponse{}, err
	}
	resp.RefreshToken = value
	return resp, nil
}

// redeemCode applies protocol's two-step redemption decision to the code of req from the Client clientID, and returns the time it was redeemed at.
func (s *Server) redeemCode(ctx context.Context, clientID string, req protocol.TokenRequest) (store.Code, time.Time, error) {
	stored, code, err := load(ctx, req.Code, s.config.Codes.Code, protocolCode)
	if err != nil {
		return store.Code{}, time.Time{}, err
	}
	now := s.config.Clock()
	effect, perr := protocol.Redeem(code, clientID, req, now)
	if effect == protocol.ConsumeCode {
		if stored, code, err = load(ctx, req.Code, s.config.Codes.ConsumeCode, protocolCode); err != nil {
			return store.Code{}, time.Time{}, err
		}
		now = s.config.Clock()
		effect, perr = protocol.Consumed(code, now)
	}
	if err := s.apply(ctx, effect, stored.Grant.ID, nil, perr); err != nil {
		return store.Code{}, time.Time{}, err
	}
	return stored, now, nil
}

// refresh issues an access token for the refresh token of req from client, rotating the refresh token when protocol decides so.
func (s *Server) refresh(ctx context.Context, client protocol.Client, req protocol.TokenRequest) (wire.TokenResponse, error) {
	stored, token, err := load(ctx, req.RefreshToken, s.config.Tokens.RefreshToken, protocolRefreshToken)
	if err != nil {
		return wire.TokenResponse{}, err
	}
	now := s.config.Clock()
	effect, scopes, perr := protocol.Refresh(token, client, req, s.config.Scopes, s.config.ReuseConfidentialRefreshTokens, now)
	var next string
	if effect == protocol.RotateRefreshToken {
		value, valueHash, err := s.secret()
		if err != nil {
			return wire.TokenResponse{}, err
		}
		successor := storeRefreshToken(valueHash, stored.Grant, protocol.Successor(*token))
		rotate := func(ctx context.Context, hash []byte) (store.RefreshToken, error) {
			return s.config.Tokens.RotateRefreshToken(ctx, hash, successor)
		}
		if stored, token, err = load(ctx, req.RefreshToken, rotate, protocolRefreshToken); err != nil {
			return wire.TokenResponse{}, err
		}
		now = s.config.Clock()
		effect, perr = protocol.Rotated(token, now)
		next = value
	}
	if err := s.apply(ctx, effect, stored.Grant.ID, nil, perr); err != nil {
		return wire.TokenResponse{}, err
	}
	resp, err := s.issueToken(ctx, stored.Grant, scopes, now, stored.ExpiresAt)
	if err != nil {
		return wire.TokenResponse{}, err
	}
	resp.RefreshToken = next
	return resp, nil
}

// clientCredentials issues an access token of a new Grant to client for itself.
func (s *Server) clientCredentials(ctx context.Context, client protocol.Client, req protocol.TokenRequest) (wire.TokenResponse, error) {
	scopes, perr := protocol.ClientCredentials(client, req, s.config.Scopes)
	if perr != nil {
		return wire.TokenResponse{}, oauthError(perr)
	}
	grantID, err := s.random()
	if err != nil {
		return wire.TokenResponse{}, err
	}
	now := s.config.Clock()
	return s.issueToken(ctx, store.Grant{ID: grantID, ClientID: client.ID, Scopes: scopes}, scopes, now, now.Add(s.config.AccessTokenLifetime))
}

// RevocationHandler returns the revocation endpoint.
func (s *Server) RevocationHandler() http.Handler {
	return http.HandlerFunc(s.revoke)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if err := s.revocation(r); err != nil {
		wire.WriteError(w, responseError(err), wire.Challenge(r))
		return
	}
	w.WriteHeader(http.StatusOK)
}

// revocation revokes the token of the revocation request r, its Grant for a refresh token.
func (s *Server) revocation(r *http.Request) error {
	token, credentials, werr := wire.ParseRevocationRequest(r)
	if werr != nil {
		return werr
	}
	ctx, c := r.Context(), protocol.Credentials(credentials)
	client, err := s.identify(ctx, c)
	if err != nil {
		return err
	}
	if perr := protocol.ValidateRevocationRequest(client, token, c, s.config.SecretHasher.Verify); perr != nil {
		return oauthError(perr)
	}
	storedRefresh, refresh, err := load(ctx, token, s.config.Tokens.RefreshToken, protocolRefreshToken)
	if err != nil {
		return err
	}
	if refresh != nil {
		effect, perr := protocol.RevokeRefreshToken(*refresh, client.ID, s.config.Clock())
		return s.apply(ctx, effect, storedRefresh.Grant.ID, nil, perr)
	}
	stored, access, err := load(ctx, token, s.config.Tokens.Token, protocolToken)
	if err != nil {
		return err
	}
	effect, perr := protocol.RevokeAccessToken(access, client.ID, s.config.Clock())
	return s.apply(ctx, effect, stored.Grant.ID, stored.Hash, perr)
}

// IntrospectionHandler returns the introspection endpoint, which answers invalid client credentials with 401.
func (s *Server) IntrospectionHandler() http.Handler {
	return http.HandlerFunc(s.introspect)
}

func (s *Server) introspect(w http.ResponseWriter, r *http.Request) {
	resp, err := s.introspection(r)
	if err != nil {
		wire.WriteIntrospectionError(w, responseError(err))
		return
	}
	wire.WriteIntrospection(w, resp)
}

// introspection answers the introspection request r; only access tokens can be active.
func (s *Server) introspection(r *http.Request) (wire.IntrospectionResponse, error) {
	token, credentials, werr := wire.ParseIntrospectionRequest(r)
	if werr != nil {
		return wire.IntrospectionResponse{}, werr
	}
	ctx, c := r.Context(), protocol.Credentials(credentials)
	client, err := s.identify(ctx, c)
	if err != nil {
		return wire.IntrospectionResponse{}, err
	}
	if perr := protocol.ValidateIntrospectionRequest(client, token, c, s.config.SecretHasher.Verify); perr != nil {
		return wire.IntrospectionResponse{}, oauthError(perr)
	}
	_, access, err := load(ctx, token, s.config.Tokens.Token, protocolToken)
	if err != nil {
		return wire.IntrospectionResponse{}, err
	}
	active := protocol.Introspect(access, client.ID, s.config.Clock())
	if active == nil {
		return wire.IntrospectionResponse{}, nil
	}
	return wire.IntrospectionResponse{
		Active:    true,
		Scope:     strings.Join(active.Scopes, " "),
		ClientID:  active.ClientID,
		Subject:   active.Subject,
		ExpiresAt: active.ExpiresAt.Unix(),
		Audience:  active.Audience,
	}, nil
}

// apply applies effect to the Grant grantID or the access token with tokenHash and returns perr, protocol's decision with it, as an error response.
func (s *Server) apply(ctx context.Context, effect protocol.Effect, grantID string, tokenHash []byte, perr *protocol.Error) error {
	var err error
	switch effect {
	case protocol.RevokeGrant:
		err = s.config.Tokens.RevokeGrant(ctx, grantID)
	case protocol.RevokeToken:
		err = s.config.Tokens.RevokeToken(ctx, tokenHash)
	}
	if err != nil {
		return err
	}
	if perr != nil {
		return oauthError(perr)
	}
	return nil
}

// issueToken creates an access token of grant with scopes at now, expiring at the latest at limit.
func (s *Server) issueToken(ctx context.Context, grant store.Grant, scopes []string, now, limit time.Time) (wire.TokenResponse, error) {
	value, valueHash, err := s.secret()
	if err != nil {
		return wire.TokenResponse{}, err
	}
	expiresAt := protocol.TokenExpiry(now, s.config.AccessTokenLifetime, limit)
	err = s.config.Tokens.CreateToken(ctx, store.Token{
		Hash:      valueHash,
		Grant:     grant,
		Scopes:    scopes,
		Audience:  grant.Audience,
		ExpiresAt: expiresAt,
	})
	if err := creationError(err); err != nil {
		return wire.TokenResponse{}, err
	}
	return wire.TokenResponse{
		AccessToken: value,
		TokenType:   "Bearer",
		ExpiresIn:   seconds(expiresAt.Sub(now)),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

// creationError returns the error response for err from creating a token.
func creationError(err error) error {
	if perr := protocol.TokenCreated(errors.Is(err, store.ErrRevoked)); perr != nil {
		return oauthError(perr)
	}
	return err
}

// seconds returns d in whole seconds, rounded up.
func seconds(d time.Duration) int64 {
	return int64((d + time.Second - 1) / time.Second)
}

// load loads the entity stored under the hash of value with get, as stored and as protocol sees it, nil when unknown.
func load[S, P any](ctx context.Context, value string, get func(context.Context, []byte) (S, error), convert func(S) P) (S, *P, error) {
	var none S
	stored, err := get(ctx, hash(value))
	if errors.Is(err, store.ErrNotFound) {
		return none, nil, nil
	}
	if err != nil {
		return none, nil, err
	}
	p := convert(stored)
	return stored, &p, nil
}

// identify loads the Client that c identifies, or nil when there is none.
func (s *Server) identify(ctx context.Context, c protocol.Credentials) (*protocol.Client, error) {
	clientID, perr := protocol.Identify(c)
	if perr != nil {
		return nil, oauthError(perr)
	}
	return s.client(ctx, clientID)
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
	return protocol.Client{
		ID:            c.ID,
		Public:        c.Type == store.Public,
		RedirectURIs:  c.RedirectURIs,
		SecretHash:    c.SecretHash,
		AllowedScopes: c.AllowedScopes,
		DefaultScopes: c.DefaultScopes,
		GrantTypes:    c.GrantTypes,
		Introspect:    c.Introspect,
	}
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

func protocolRefreshToken(t store.RefreshToken) protocol.RefreshToken {
	return protocol.RefreshToken{
		ClientID:  t.Grant.ClientID,
		Scopes:    t.Grant.Scopes,
		ExpiresAt: t.ExpiresAt,
		Rotated:   t.Rotated,
	}
}

func protocolToken(t store.Token) protocol.Token {
	return protocol.Token{
		ClientID:  t.Grant.ClientID,
		Subject:   t.Grant.Subject,
		Scopes:    t.Scopes,
		Audience:  t.Audience,
		ExpiresAt: t.ExpiresAt,
	}
}

func storeRefreshToken(hash []byte, grant store.Grant, t protocol.RefreshToken) store.RefreshToken {
	return store.RefreshToken{Hash: hash, Grant: grant, ExpiresAt: t.ExpiresAt, Rotated: t.Rotated}
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
