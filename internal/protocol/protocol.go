package protocol

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// OAuth error codes.
const (
	invalidRequest          = "invalid_request"
	accessDenied            = "access_denied"
	invalidClient           = "invalid_client"
	invalidGrant            = "invalid_grant"
	unsupportedGrantType    = "unsupported_grant_type"
	unsupportedResponseType = "unsupported_response_type"
)

// methodS256 is the only supported code challenge method.
const methodS256 = "S256"

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

// Authorize validates r for client (nil when unknown); on error, the returned request has a RedirectURI only when the error may be redirected.
func Authorize(client *Client, r AuthorizationParams, expiresAt time.Time) (AuthorizationRequest, *Error) {
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
		Scopes:              strings.Fields(r.Scope),
		CodeChallenge:       r.CodeChallenge,
		CodeChallengeMethod: r.CodeChallengeMethod,
		ExpiresAt:           expiresAt,
	}
	switch {
	case r.ResponseType == "":
		return a, &Error{invalidRequest, "response_type required"}
	case r.ResponseType != "code":
		return a, &Error{unsupportedResponseType, "response_type must be code"}
	case r.CodeChallenge == "":
		return a, &Error{invalidRequest, "code challenge required"}
	case r.CodeChallengeMethod != methodS256:
		return a, &Error{invalidRequest, "transform algorithm not supported"}
	case !s256Challenge(r.CodeChallenge):
		return a, &Error{invalidRequest, "malformed code challenge"}
	}
	return a, nil
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
	Used                bool
}

// IssueCode binds a code for a to the Resource Owner subject and the granted scopes.
func IssueCode(a AuthorizationRequest, subject string, scopes []string, expiresAt time.Time) (Code, *Error) {
	if subject == "" {
		return Code{}, &Error{invalidRequest, "subject required"}
	}
	if len(a.Scopes) > 0 && len(scopes) == 0 {
		return Code{}, &Error{invalidRequest, "no scopes granted; deny the request instead"}
	}
	return Code{
		ClientID:            a.ClientID,
		Subject:             subject,
		Scopes:              scopes,
		RedirectURI:         a.RedirectURI,
		CodeChallenge:       a.CodeChallenge,
		CodeChallengeMethod: a.CodeChallengeMethod,
		ExpiresAt:           expiresAt,
	}, nil
}

// TokenRequest is the parameters of a token request.
type TokenRequest struct {
	GrantType     string
	Code          string
	RedirectURI   string
	ClientID      string
	CodeVerifier  string
	ClientSecret  string
	Authorization string
}

// ValidateTokenRequest checks r for client, which is nil when unknown, before its code is consumed.
func ValidateTokenRequest(client *Client, r TokenRequest) *Error {
	switch {
	case r.GrantType == "":
		return &Error{invalidRequest, "grant_type required"}
	case r.GrantType != "authorization_code":
		return &Error{unsupportedGrantType, "grant_type must be authorization_code"}
	case r.Code == "":
		return &Error{invalidRequest, "code required"}
	case r.CodeVerifier == "":
		return &Error{invalidRequest, "code_verifier required"}
	case client == nil || !client.Public:
		return &Error{invalidClient, "unknown or confidential client"}
	case r.Authorization != "" || r.ClientSecret != "":
		return &Error{invalidClient, "public clients do not authenticate"}
	}
	return nil
}

// Redeem decides whether r may redeem code (nil when unknown) at now, and whether to revoke its Grant.
func Redeem(code *Code, r TokenRequest, now time.Time) (revokeGrant bool, err *Error) {
	if code == nil {
		return false, &Error{invalidGrant, "invalid code"}
	}
	if err := bound(code, r); err != nil {
		return false, err
	}
	switch {
	case code.Used:
		return true, &Error{invalidGrant, "code already used"}
	case !now.Before(code.ExpiresAt):
		return false, &Error{invalidGrant, "code expired"}
	}
	return false, nil
}

// TokenCreated decides on the result of creating a token, which fails when its Grant was revoked.
func TokenCreated(grantRevoked bool) *Error {
	if grantRevoked {
		return &Error{invalidGrant, "grant revoked"}
	}
	return nil
}

// bound checks that r comes from the Client the code was issued to.
func bound(code *Code, r TokenRequest) *Error {
	switch {
	case code.ClientID != r.ClientID:
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
