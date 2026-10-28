package protocol

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
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
	invalidToken            = "invalid_token"
	insufficientScope       = "insufficient_scope"
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
	// Introspect lets a confidential Client call the introspection endpoint.
	Introspect bool
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
	// Error is the error the request failed with, which Denied returns.
	Error *Error
}

// Authorize validates r for client (nil when unknown) and the supported scopes; it fails only when the Client or its redirect URI cannot be trusted, and keeps the other errors in the request.
func Authorize(client *Client, r AuthorizationParams, supported []string, expiresAt time.Time) (AuthorizationRequest, *Error) {
	if client == nil {
		return AuthorizationRequest{}, &Error{invalidRequest, "unknown client"}
	}
	redirectURI, ok := client.redirectURI(r.RedirectURI)
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
	a.Scopes, a.Error = validateAuthorization(client, r, supported)
	return a, nil
}

// validateAuthorization returns the scopes of r for client, or the error r fails with.
func validateAuthorization(client *Client, r AuthorizationParams, supported []string) ([]string, *Error) {
	switch {
	case r.ResponseType == "":
		return nil, &Error{invalidRequest, "response_type required"}
	case r.ResponseType != "code":
		return nil, &Error{unsupportedResponseType, "response_type must be code"}
	case !client.Allows(AuthorizationCodeGrant):
		return nil, grantTypeNotAllowed()
	case r.CodeChallenge == "":
		return nil, &Error{invalidRequest, "code challenge required"}
	case r.CodeChallengeMethod != methodS256:
		return nil, &Error{invalidRequest, "transform algorithm not supported"}
	case !s256Challenge(r.CodeChallenge):
		return nil, &Error{invalidRequest, "malformed code challenge"}
	}
	return resolveScopes(r.Scope, supported, client.AllowedScopes, client.DefaultScopes)
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

// redirectURI returns requested, or the only registered redirect URI when it is empty, and whether c may be redirected to it.
func (c *Client) redirectURI(requested string) (string, bool) {
	if requested == "" {
		if len(c.RedirectURIs) != 1 {
			return "", false
		}
		requested = c.RedirectURIs[0]
	}
	for _, r := range c.RedirectURIs {
		if validRedirectURI(r) && matchRedirectURI(r, requested) {
			return requested, true
		}
	}
	return "", false
}

// matchRedirectURI reports whether requested matches the registered redirect URI, ignoring loopback ports.
func matchRedirectURI(registered, requested string) bool {
	if registered == requested {
		return true
	}
	portless, loopback := withoutPort(requested)
	p, ok := withoutPort(registered)
	return loopback && ok && p == portless
}

// validRedirectURI reports whether the registered uri may be used as a redirect URI.
func validRedirectURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || !u.IsAbs() || strings.Contains(uri, "#") || strings.ContainsFunc(uri, notURIChar) || !strictURISyntax(uri, u) {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Hostname() != "" && u.User == nil
	case "http":
		_, loopback := withoutPort(uri)
		return loopback
	}
	return reverseDomainName(u.Scheme)
}

// notURIChar reports whether c may not appear in a URI (RFC 3986, Appendix A).
func notURIChar(c rune) bool {
	return c <= ' ' || c > '~' || strings.ContainsRune("\"<>\\^`{|}", c)
}

// strictURISyntax reports whether uri, parsed as u, keeps the parts of the RFC 3986 grammar that url.Parse does not check.
func strictURISyntax(uri string, u *url.URL) bool {
	for rest := uri; strings.Contains(rest, "%"); {
		_, rest, _ = strings.Cut(rest, "%")
		if len(rest) < 2 || !isHex(rest[0]) || !isHex(rest[1]) {
			return false
		}
	}
	unbracketed := uri
	if strings.HasPrefix(u.Host, "[") {
		unbracketed = strings.Replace(uri, u.Host, "", 1)
	}
	var authority string
	if hierPart := uri[len(u.Scheme)+1:]; strings.HasPrefix(hierPart, "//") {
		authority = hierPart[2:]
		if i := strings.IndexAny(authority, "/?"); i >= 0 {
			authority = authority[:i]
		}
	}
	host := authority[strings.LastIndex(authority, "@")+1:]
	if i := strings.LastIndexByte(host, ':'); i >= 0 && strings.Trim(host[i+1:], "0123456789") == "" {
		host = host[:i]
	}
	return !strings.ContainsAny(unbracketed, "[]") && strings.Count(authority, "@") <= 1 && (strings.HasPrefix(host, "[") || !strings.Contains(host, ":"))
}

// isHex reports whether c is a hexadecimal digit.
func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// reverseDomainName reports whether scheme is a domain name in reverse order, such as com.example.app.
func reverseDomainName(scheme string) bool {
	labels := strings.Split(scheme, ".")
	if len(labels) < 2 {
		return false
	}
	return !slices.ContainsFunc(labels, notLabel)
}

// notLabel reports whether l is not a label of lower-case letters, digits and inner hyphens.
func notLabel(l string) bool {
	return l == "" || l[0] == '-' || l[len(l)-1] == '-' || strings.ContainsFunc(l, notLDH)
}

// notLDH reports whether c is not a lower-case letter, a digit or a hyphen.
func notLDH(c rune) bool {
	return (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-'
}

// FrameAncestors returns the origins among origins that frameAncestor accepts.
func FrameAncestors(origins []string) []string {
	var valid []string
	for _, o := range origins {
		if frameAncestor(o) {
			valid = append(valid, o)
		}
	}
	return valid
}

// frameAncestor reports whether origin is an https origin with a lower-case host name and an optional port.
func frameAncestor(origin string) bool {
	hostport, ok := strings.CutPrefix(origin, "https://")
	if !ok {
		return false
	}
	host, port, hasPort := strings.Cut(hostport, ":")
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	}
	return !slices.ContainsFunc(strings.Split(host, "."), notLabel)
}

// withoutPort returns a loopback IP redirect URI without its port.
func withoutPort(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" || u.User != nil {
		return "", false
	}
	prefix := "http://" + u.Host
	if len(uri) < len(prefix) || !strings.EqualFold(uri[:len(prefix)], prefix) {
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
	return uri[:len("http://")] + host + uri[len(prefix):], true
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

// Denied returns the error response for the denied Authorization Request a: the error it failed with, or access_denied.
func Denied(a AuthorizationRequest) *Error {
	if a.Error != nil {
		return a.Error
	}
	return &Error{accessDenied, "the resource owner denied the request"}
}

// Code is what an authorization code is bound to.
type Code struct {
	ClientID            string
	Subject             string
	Scopes              []string
	Audience            []string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	// RetainUntil is when the code may be removed, used or not.
	RetainUntil time.Time
	Used        bool
}

// Completion is the Host Application's answer to an Authorization Request.
type Completion struct {
	Subject string
	// Scopes are the granted scopes, a subset of the requested ones.
	Scopes []string
	// Audience are the Resource Servers the Resource Owner consented to, by Client identifier.
	Audience []string
}

// IssueCode binds a code for a to c, retaining it for tokenLifetime after it expires; each Resource Server in c.Audience must be in registered.
func IssueCode(a AuthorizationRequest, c Completion, registered []string, expiresAt time.Time, tokenLifetime time.Duration) (Code, *Error) {
	switch {
	case a.Error != nil:
		return Code{}, &Error{invalidRequest, "the request failed; deny it instead"}
	case c.Subject == "":
		return Code{}, &Error{invalidRequest, "subject required"}
	case len(c.Scopes) == 0:
		return Code{}, &Error{invalidRequest, "no scopes granted; deny the request instead"}
	case slices.ContainsFunc(c.Scopes, func(s string) bool { return !slices.Contains(a.Scopes, s) }):
		return Code{}, &Error{invalidRequest, "granted scope was not requested"}
	case !distinct(c.Audience):
		return Code{}, &Error{invalidRequest, "repeated Resource Server in audience"}
	case slices.ContainsFunc(c.Audience, func(id string) bool { return !slices.Contains(registered, id) }):
		return Code{}, &Error{invalidRequest, "audience names an unknown Resource Server"}
	}
	return Code{
		ClientID:            a.ClientID,
		Subject:             c.Subject,
		Scopes:              slices.DeleteFunc(slices.Clone(a.Scopes), func(s string) bool { return !slices.Contains(c.Scopes, s) }),
		Audience:            slices.Clone(c.Audience),
		RedirectURI:         a.RedirectURI,
		CodeChallenge:       a.CodeChallenge,
		CodeChallengeMethod: a.CodeChallengeMethod,
		ExpiresAt:           expiresAt,
		RetainUntil:         expiresAt.Add(tokenLifetime),
	}, nil
}

// distinct reports whether no value occurs twice in s.
func distinct(s []string) bool {
	return len(slices.Compact(slices.Sorted(slices.Values(s)))) == len(s)
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
	CodeVerifier string
	RefreshToken string
	Scope        string
}

// Credentials is how a request identifies and authenticates its Client.
type Credentials struct {
	ClientID     string
	ClientSecret string
	// AuthScheme is the scheme of the Authorization header, or "" without one.
	AuthScheme  string
	BasicID     string
	BasicSecret string
}

// Identify returns the identifier of the Client r comes from, rejecting more than one authentication method.
func Identify(r Credentials) (string, *Error) {
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
func Authenticate(client *Client, r Credentials, verify func(hash, secret string) bool) *Error {
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

// ValidateTokenRequest checks r with credentials c for client, which is nil when unknown, before its code or refresh token is loaded.
func ValidateTokenRequest(client *Client, r TokenRequest, c Credentials, verify func(hash, secret string) bool) *Error {
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
	if err := Authenticate(client, c, verify); err != nil {
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
	// RevokeToken asks to revoke the access token.
	RevokeToken
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

// GrantLifetime is how long client can use a Grant: the Refresh Token Family lifetime when it may use refresh tokens, else the access token lifetime.
func GrantLifetime(client Client, access, refresh time.Duration) time.Duration {
	if client.Allows(RefreshTokenGrant) {
		return refresh
	}
	return access
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

// ValidateRevocationRequest checks a revocation request for token with credentials c for client, which is nil when unknown, before the token is loaded.
func ValidateRevocationRequest(client *Client, token string, c Credentials, verify func(hash, secret string) bool) *Error {
	if token == "" {
		return &Error{invalidRequest, "token required"}
	}
	return Authenticate(client, c, verify)
}

// Token is what an access token is bound to.
type Token struct {
	ClientID  string
	Subject   string
	Scopes    []string
	Audience  []string
	ExpiresAt time.Time
}

// RevokeRefreshToken decides on revoking token, and so its Grant, for the Client clientID at now.
func RevokeRefreshToken(token RefreshToken, clientID string, now time.Time) (Effect, *Error) {
	return revoke(token.ClientID, token.ExpiresAt, RevokeGrant, clientID, now)
}

// RevokeAccessToken decides on revoking token (nil when unknown) for the Client clientID at now.
func RevokeAccessToken(token *Token, clientID string, now time.Time) (Effect, *Error) {
	if token == nil {
		return NoEffect, nil
	}
	return revoke(token.ClientID, token.ExpiresAt, RevokeToken, clientID, now)
}

// revoke decides on revoking a token of owner expiring at expiresAt with effect.
func revoke(owner string, expiresAt time.Time, effect Effect, clientID string, now time.Time) (Effect, *Error) {
	switch {
	case !now.Before(expiresAt):
		return NoEffect, nil
	case owner != clientID:
		return NoEffect, &Error{invalidGrant, "token was issued to another client"}
	}
	return effect, nil
}

// ValidateIntrospectionRequest checks an introspection request for token with credentials c for client, which is nil when unknown, before the token is loaded; the caller is checked first.
func ValidateIntrospectionRequest(client *Client, token string, c Credentials, verify func(hash, secret string) bool) *Error {
	if err := Authenticate(client, c, verify); err != nil {
		return err
	}
	switch {
	case client.Public:
		return &Error{invalidClient, "client authentication required"}
	case !client.Introspect:
		return &Error{unauthorizedClient, "client may not introspect"}
	case token == "":
		return &Error{invalidRequest, "token required"}
	}
	return nil
}

// Introspect returns token (nil when unknown) when it is active at now for the Client clientID, and nil otherwise; a token with an audience is active only for a Client in it.
func Introspect(token *Token, clientID string, now time.Time) *Token {
	switch {
	case token == nil, !now.Before(token.ExpiresAt):
		return nil
	case len(token.Audience) > 0 && !slices.Contains(token.Audience, clientID):
		return nil
	}
	return token
}

// Access decides whether an access token, active or not, with scopes may reach a resource that requires the scopes required.
func Access(active bool, scopes, required []string) *Error {
	switch {
	case !active:
		return &Error{invalidToken, "access token not active"}
	case slices.ContainsFunc(required, func(s string) bool { return !slices.Contains(scopes, s) }):
		return &Error{insufficientScope, "access token lacks a required scope"}
	}
	return nil
}

// SecureTLS reports whether state, nil without TLS, is TLS 1.2 or later with a secure cipher suite.
func SecureTLS(state *tls.ConnectionState) bool {
	if state == nil || state.Version < tls.VersionTLS12 {
		return false
	}
	return !slices.ContainsFunc(tls.InsecureCipherSuites(), func(c *tls.CipherSuite) bool { return c.ID == state.CipherSuite })
}

// InsecureTransport returns the error response for a request without SecureTLS that the Host Application does not declare secure.
func InsecureTransport() *Error {
	return &Error{invalidRequest, "TLS required"}
}

// SecureEndpoint decides whether access tokens may be sent to endpoint: only to an https URL.
func SecureEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "https"
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
