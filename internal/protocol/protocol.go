package protocol

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
)

// OAuth error codes.
const (
	invalidRequest          = "invalid_request"
	accessDenied            = "access_denied"
	invalidClient           = "invalid_client"
	invalidGrant            = "invalid_grant"
	invalidScope            = "invalid_scope"
	unauthorizedClient      = "unauthorized_client"
	unsupportedGrantType    = "unsupported_grant_type"
	unsupportedResponseType = "unsupported_response_type"
)

// methodS256 is the only supported code challenge method.
const methodS256 = "S256"

// Grant types of the token endpoint.
const (
	AuthorizationCodeGrant = "authorization_code"
	RefreshTokenGrant      = "refresh_token"
	ClientCredentialsGrant = "client_credentials"
)

// Error is an OAuth error response.
type Error struct {
	Code        string
	Description string
}

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// Client is a registered Client as protocol sees it.
type Client struct {
	ID           string
	Public       bool
	RedirectURIs []string
	SecretHash   string
	// AllowedScopes are the scopes the Client may request.
	AllowedScopes []string
	// DefaultScopes are requested for the Client when it omits scope.
	DefaultScopes []string
	// GrantTypes are the grant types the Client may use, authorization_code and refresh_token when empty.
	GrantTypes []string
}

// Allows reports whether c may use grantType.
func (c Client) Allows(grantType string) bool {
	if len(c.GrantTypes) == 0 {
		return grantType == AuthorizationCodeGrant || grantType == RefreshTokenGrant
	}
	return slices.Contains(c.GrantTypes, grantType)
}

// AuthorizationParams is the parameters of an authorization request.
type AuthorizationParams struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// AuthorizationRequest is a validated Authorization Request.
type AuthorizationRequest struct {
	ClientID            string
	RedirectURI         string
	State               string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// Authorize validates r for client (nil when unknown) and the supported scopes; on error, the returned request has a RedirectURI only when the error may be redirected.
func Authorize(client *Client, r AuthorizationParams, supported []string, expiresAt time.Time) (AuthorizationRequest, *Error) {
	if client == nil {
		return AuthorizationRequest{}, &Error{invalidRequest, "unknown client"}
	}
	redirectURI, ok := resolveRedirectURI(client.RedirectURIs, r.RedirectURI)
	if !ok {
		return AuthorizationRequest{}, &Error{invalidRequest, "invalid redirect_uri"}
	}
	a := AuthorizationRequest{
		ClientID:            client.ID,
		RedirectURI:         redirectURI,
		State:               r.State,
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
		ExpiresAt:           expiresAt,
	}
	switch {
	case r.ResponseType == "":
		return a, &Error{invalidRequest, "response_type required"}
	case r.ResponseType != "code":
		return a, &Error{unsupportedResponseType, "response_type must be code"}
	case !client.Allows(AuthorizationCodeGrant):
		return a, grantTypeNotAllowed()
	case r.CodeChallenge == "":
		return a, &Error{invalidRequest, "code challenge required"}
	case r.CodeChallengeMethod != methodS256:
		return a, &Error{invalidRequest, "transform algorithm not supported"}
	case !s256Challenge(r.CodeChallenge):
		return a, &Error{invalidRequest, "malformed code challenge"}
	}
	scopes, err := resolveScopes(r.Scope, supported, client.AllowedScopes, client.DefaultScopes)
	if err != nil {
		return a, err
	}
	a.Scopes = scopes
	return a, nil
}

// resolveScopes returns the distinct scopes of the space-separated requested, or the defaults when it is empty, failing unless each is supported and allowed.
func resolveScopes(requested string, supported, allowed, defaults []string) ([]string, *Error) {
	scopes := defaults
	if requested != "" {
		scopes = strings.Split(requested, " ")
	}
	var resolved []string
	for _, s := range scopes {
		switch {
		case s == "" || slices.Contains(resolved, s):
		case !ScopeToken(s):
			return nil, &Error{invalidScope, "malformed scope"}
		case !slices.Contains(supported, s) || !slices.Contains(allowed, s):
			return nil, &Error{invalidScope, "scope not available to the client"}
		default:
			resolved = append(resolved, s)
		}
	}
	if len(resolved) == 0 {
		return nil, &Error{invalidScope, "scope required"}
	}
	return resolved, nil
}

// ScopeToken reports whether s is a scope-token: one or more printable ASCII characters other than space, '"' and '\'.
func ScopeToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func resolveRedirectURI(registered []string, requested string) (string, bool) {
	if requested == "" {
		if len(registered) == 1 {
			return registered[0], registered[0] != ""
		}
		return "", false
	}
	return requested, matchRedirectURI(registered, requested)
}

// matchRedirectURI reports whether requested is a registered redirect URI, ignoring loopback ports.
func matchRedirectURI(registered []string, requested string) bool {
	portless, loopback := withoutPort(requested)
	for _, r := range registered {
		if r == requested {
			return true
		}
		if p, ok := withoutPort(r); loopback && ok && p == portless {
			return true
		}
	}
	return false
}

// withoutPort returns a loopback IP redirect URI without its port.
func withoutPort(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" || u.User != nil || !strings.HasPrefix(uri, "http://"+u.Host) {
		return "", false
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil || !addr.IsLoopback() {
		return "", false
	}
	host := u.Hostname()
	if addr.Is6() {
		host = "[" + host + "]"
	}
	return "http://" + host + uri[len("http://"+u.Host):], true
}

// Pending decides whether a is still pending at now; a is nil when unknown, completed or denied.
func Pending(a *AuthorizationRequest, now time.Time) *Error {
	switch {
	case a == nil:
		return &Error{invalidRequest, "unknown authorization request"}
	case !now.Before(a.ExpiresAt):
		return &Error{invalidRequest, "authorization request expired"}
	}
	return nil
}

// Denied returns the error response for a denied Authorization Request.
func Denied() *Error {
	return &Error{accessDenied, "the resource owner denied the request"}
}

// Code is what an authorization code is bound to.
type Code struct {
	ClientID            string
	Subject             string
	Scopes              []string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	// RetainUntil is when the code may be removed, used or not.
	RetainUntil time.Time
	Used        bool
}

// IssueCode binds a code for a to the Resource Owner subject and the granted scopes, a subset of the requested ones, retaining it for tokenLifetime after it expires.
func IssueCode(a AuthorizationRequest, subject string, granted []string, expiresAt time.Time, tokenLifetime time.Duration) (Code, *Error) {
	switch {
	case subject == "":
		return Code{}, &Error{invalidRequest, "subject required"}
	case len(granted) == 0:
		return Code{}, &Error{invalidRequest, "no scopes granted; deny the request instead"}
	case slices.ContainsFunc(granted, func(s string) bool { return !slices.Contains(a.Scopes, s) }):
		return Code{}, &Error{invalidRequest, "granted scope was not requested"}
	}
	return Code{
		ClientID:            a.ClientID,
		Subject:             subject,
		Scopes:              slices.DeleteFunc(slices.Clone(a.Scopes), func(s string) bool { return !slices.Contains(granted, s) }),
		RedirectURI:         a.RedirectURI,
		CodeChallenge:       a.CodeChallenge,
		CodeChallengeMethod: a.CodeChallengeMethod,
		ExpiresAt:           expiresAt,
		RetainUntil:         expiresAt.Add(tokenLifetime),
	}, nil
}

// TokenExpiry is when a token issued at now with lifetime expires, at the latest at limit.
func TokenExpiry(now time.Time, lifetime time.Duration, limit time.Time) time.Time {
	if expiresAt := now.Add(lifetime); expiresAt.Before(limit) {
		return expiresAt
	}
	return limit
}

// grantTypeNotAllowed is the error for a Client using a grant type it may not use.
func grantTypeNotAllowed() *Error {
	return &Error{unauthorizedClient, "grant type not allowed for the client"}
}

// TokenRequest is the parameters of a token request.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
	RefreshToken string
	Scope        string
	ClientSecret string
	// AuthScheme is the scheme of the Authorization header, or "" without one.
	AuthScheme  string
	BasicID     string
	BasicSecret string
}

// Identify returns the identifier of the Client r comes from, rejecting more than one authentication method.
func Identify(r TokenRequest) (string, *Error) {
	switch {
	case r.AuthScheme != "" && r.ClientSecret != "":
		return "", &Error{invalidRequest, "more than one client authentication method"}
	case r.AuthScheme != "Basic":
		return r.ClientID, nil
	case r.ClientID != "" && r.ClientID != r.BasicID:
		return "", &Error{invalidClient, "client_id does not match the Authorization header"}
	}
	return r.BasicID, nil
}

// Authenticate decides whether r authenticates client, which is nil when unknown; verify reports whether a secret matches a secret hash.
func Authenticate(client *Client, r TokenRequest, verify func(hash, secret string) bool) *Error {
	secret, presented := r.ClientSecret, r.ClientSecret != ""
	switch r.AuthScheme {
	case "":
	case "Basic":
		secret, presented = r.BasicSecret, true
	default:
		return &Error{invalidClient, "unsupported client authentication method"}
	}
	switch {
	case client == nil:
		return &Error{invalidClient, "unknown client"}
	case client.Public && presented:
		return &Error{invalidClient, "public clients do not authenticate"}
	case client.Public:
		return nil
	case !presented:
		return &Error{invalidClient, "client authentication required"}
	case client.SecretHash == "" || !verify(client.SecretHash, secret):
		return &Error{invalidClient, "invalid client secret"}
	}
	return nil
}

// ValidateTokenRequest checks r for client, which is nil when unknown, before its code or refresh token is loaded.
func ValidateTokenRequest(client *Client, r TokenRequest, verify func(hash, secret string) bool) *Error {
	switch r.GrantType {
	case "":
		return &Error{invalidRequest, "grant_type required"}
	case AuthorizationCodeGrant:
		switch {
		case r.Code == "":
			return &Error{invalidRequest, "code required"}
		case r.CodeVerifier == "":
			return &Error{invalidRequest, "code_verifier required"}
		}
	case RefreshTokenGrant:
		if r.RefreshToken == "" {
			return &Error{invalidRequest, "refresh_token required"}
		}
	case ClientCredentialsGrant:
	default:
		return &Error{unsupportedGrantType, "grant_type must be authorization_code, refresh_token or client_credentials"}
	}
	if err := Authenticate(client, r, verify); err != nil {
		return err
	}
	if !client.Allows(r.GrantType) {
		return grantTypeNotAllowed()
	}
	return nil
}

// Effect is a Store operation protocol asks the server to apply.
type Effect int

const (
	// NoEffect asks for no Store operation.
	NoEffect Effect = iota
	// ConsumeCode asks to consume the code atomically and pass the result to Consumed.
	ConsumeCode
	// RevokeGrant asks to revoke the Grant of the code or refresh token.
	RevokeGrant
	// RotateRefreshToken asks to replace the refresh token by a new one atomically and pass the result to Rotated.
	RotateRefreshToken
)

// Redeem decides whether r from the Client clientID may redeem code (nil when unknown) at now.
func Redeem(code *Code, clientID string, r TokenRequest, now time.Time) (Effect, *Error) {
	if code != nil {
		if err := bound(code, clientID, r); err != nil {
			return NoEffect, err
		}
	}
	if effect, err := Consumed(code, now); err != nil {
		return effect, err
	}
	return ConsumeCode, nil
}

// Consumed decides on the code ConsumeCode returned at now, nil when unknown.
func Consumed(code *Code, now time.Time) (Effect, *Error) {
	switch {
	case code == nil:
		return NoEffect, &Error{invalidGrant, "invalid code"}
	case code.Used:
		return RevokeGrant, &Error{invalidGrant, "code already used"}
	case !now.Before(code.ExpiresAt), !now.Before(code.RetainUntil):
		return NoEffect, &Error{invalidGrant, "code expired"}
	}
	return NoEffect, nil
}

// RefreshToken is what a refresh token is bound to.
type RefreshToken struct {
	ClientID string
	// Scopes are the scopes of the Grant.
	Scopes    []string
	ExpiresAt time.Time
	Rotated   bool
}

// IssueRefreshToken is the first refresh token of the Refresh Token Family of code redeemed at now by client, nil when client may not use refresh tokens.
func IssueRefreshToken(client Client, code Code, now time.Time, lifetime time.Duration) *RefreshToken {
	if !client.Allows(RefreshTokenGrant) {
		return nil
	}
	return &RefreshToken{ClientID: code.ClientID, Scopes: code.Scopes, ExpiresAt: TokenExpiry(now, lifetime, code.RetainUntil)}
}

// Successor is the refresh token that replaces token in its Refresh Token Family.
func Successor(token RefreshToken) RefreshToken {
	token.Rotated = false
	return token
}

// Refresh decides whether r from client may use token (nil when unknown) at now, and returns the scopes of the new access token; only confidential Clients may reuse their token.
func Refresh(token *RefreshToken, client Client, r TokenRequest, supported []string, reuseConfidential bool, now time.Time) (Effect, []string, *Error) {
	if token != nil && token.ClientID != client.ID {
		return NoEffect, nil, &Error{invalidGrant, "refresh token was issued to another client"}
	}
	if effect, err := Rotated(token, now); err != nil {
		return effect, nil, err
	}
	scopes, err := refreshScopes(r.Scope, token.Scopes, supported, client.AllowedScopes)
	if err != nil {
		return NoEffect, nil, err
	}
	if client.Public || !reuseConfidential {
		return RotateRefreshToken, scopes, nil
	}
	return NoEffect, scopes, nil
}

// refreshScopes resolves the requested scopes of a refresh against the granted ones that are still supported and allowed, all of those when requested is empty.
func refreshScopes(requested string, granted, supported, allowed []string) ([]string, *Error) {
	available := slices.DeleteFunc(slices.Clone(granted), func(s string) bool { return !slices.Contains(supported, s) || !slices.Contains(allowed, s) })
	return resolveScopes(requested, supported, available, available)
}

// Rotated decides on the refresh token RotateRefreshToken returned at now, nil when unknown.
func Rotated(token *RefreshToken, now time.Time) (Effect, *Error) {
	switch {
	case token == nil:
		return NoEffect, &Error{invalidGrant, "invalid refresh token"}
	case token.Rotated:
		return RevokeGrant, &Error{invalidGrant, "refresh token already rotated"}
	case !now.Before(token.ExpiresAt):
		return NoEffect, &Error{invalidGrant, "refresh token expired"}
	}
	return NoEffect, nil
}

// ClientCredentials decides whether r from client may obtain an access token for itself, and returns its scopes.
func ClientCredentials(client Client, r TokenRequest, supported []string) ([]string, *Error) {
	if client.Public {
		return nil, &Error{unauthorizedClient, "public clients cannot use client credentials"}
	}
	return resolveScopes(r.Scope, supported, client.AllowedScopes, client.DefaultScopes)
}

// TokenCreated decides on the result of creating a token, which fails when its Grant was revoked.
func TokenCreated(grantRevoked bool) *Error {
	if grantRevoked {
		return &Error{invalidGrant, "grant revoked"}
	}
	return nil
}

// bound checks that r from the Client clientID matches what the code is bound to.
func bound(code *Code, clientID string, r TokenRequest) *Error {
	switch {
	case code.ClientID != clientID:
		return &Error{invalidGrant, "code was issued to another client"}
	case r.RedirectURI != "" && r.RedirectURI != code.RedirectURI:
		return &Error{invalidGrant, "redirect_uri does not match"}
	case !verifyPKCE(code.CodeChallengeMethod, code.CodeChallenge, r.CodeVerifier):
		return &Error{invalidGrant, "code_verifier does not match"}
	}
	return nil
}

// verifyPKCE reports whether verifier matches challenge under method; only S256 is supported.
func verifyPKCE(method, challenge, verifier string) bool {
	if method != methodS256 || !pkceValue(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// s256Challenge reports whether v can be an S256 code challenge: the base64url encoding of a SHA-256 hash.
func s256Challenge(v string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(v)
	return err == nil && len(b) == sha256.Size
}

// pkceValue reports whether v is 43 to 128 unreserved characters (RFC 7636).
func pkceValue(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range []byte(v) {
		if !unreserved(c) {
			return false
		}
	}
	return true
}

func unreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("-._~", c) >= 0
}
