package conformance

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gofabrik/oauth21"
)

// refreshParams returns a refresh request of the public Client for refreshToken.
func refreshParams(refreshToken string) url.Values {
	return url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}
}

// tokens sends a token request that must succeed and returns its access and refresh tokens.
func (a *authorizationServer) tokens(params url.Values, header http.Header) (access, refresh string) {
	a.t.Helper()
	status, _, body := a.token(params, header)
	access, _ = body["access_token"].(string)
	refresh, _ = body["refresh_token"].(string)
	if status != http.StatusOK || access == "" {
		a.t.Fatalf("got status %d and body %v, want an access token", status, body)
	}
	return access, refresh
}

// refreshToken sends the token request params with header and returns the refresh token it gets.
func (a *authorizationServer) refreshToken(params url.Values, header http.Header) string {
	a.t.Helper()
	_, refresh := a.tokens(params, header)
	if refresh == "" {
		a.t.Fatal("got no refresh token")
	}
	return refresh
}

// publicRefreshToken redeems a code of the public Client and returns the refresh token it gets.
func (a *authorizationServer) publicRefreshToken() string {
	a.t.Helper()
	return a.refreshToken(tokenParams(a.code(authorizeParams())), nil)
}

// wantReuseRevokesGrant refreshes with token and checks that presenting token again fails and revokes its successor.
func (a *authorizationServer) wantReuseRevokesGrant(token string, request func(string) url.Values, header http.Header) {
	t := a.t
	t.Helper()
	successor := a.refreshToken(request(token), header)
	if successor == token {
		t.Fatal("got the presented refresh token back, want a new one")
	}
	status, _, body := a.token(request(token), header)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
	status, _, body = a.token(request(successor), header)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestPublicClientRefreshes checks that a public Client gets a new access token and a new refresh token for its refresh token.
func TestPublicClientRefreshes(t *testing.T) {
	a := newAuthorizationServer(t)
	first := a.publicRefreshToken()
	_, second := a.tokens(refreshParams(first), nil)
	if second == "" || second == first {
		t.Fatalf("got refresh token %q, want a new one", second)
	}
	if _, third := a.tokens(refreshParams(second), nil); third == "" || third == second {
		t.Fatalf("got refresh token %q, want a new one", third)
	}
}

// TestRotatedRefreshTokenRevokesGrant checks that presenting a rotated refresh token fails and revokes the refresh token that replaced it.
//
//conformance:covers INV-0004
func TestRotatedRefreshTokenRevokesGrant(t *testing.T) {
	a := newAuthorizationServer(t)
	a.wantReuseRevokesGrant(a.publicRefreshToken(), refreshParams, nil)
}

// TestCodeReplayRevokesRefreshToken checks that a second redemption of a code revokes the refresh token issued from it.
//
//conformance:covers INV-0001
func TestCodeReplayRevokesRefreshToken(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	_, refresh := a.tokens(params, nil)
	if status, _, _ := a.token(params, nil); status != http.StatusBadRequest {
		t.Fatalf("got status %d for a replay, want 400", status)
	}
	status, _, body := a.token(refreshParams(refresh), nil)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestConcurrentRefreshRotatesOnce checks that concurrent refreshes with one refresh token of a public Client issue at most one access token, and that the refreshes that lose revoke the Grant.
//
//conformance:covers INV-0004
func TestConcurrentRefreshRotatesOnce(t *testing.T) {
	a := newAuthorizationServer(t)
	issued := a.race(refreshParams(a.publicRefreshToken()))
	if len(issued) > 1 {
		t.Fatalf("got %d access tokens for one refresh token, want at most 1", len(issued))
	}
	for _, body := range issued {
		next, _ := body["refresh_token"].(string)
		status, _, body := a.token(refreshParams(next), nil)
		a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
	}
}

// confidentialRefreshToken redeems a code of the confidential Client and returns the refresh token it gets.
func (a *authorizationServer) confidentialRefreshToken() string {
	a.t.Helper()
	return a.refreshToken(a.confidentialCode(), basic(confidentialID, secret))
}

// confidentialRefreshParams returns a refresh request for refreshToken without Client credentials.
func confidentialRefreshParams(refreshToken string) url.Values {
	params := refreshParams(refreshToken)
	params.Del("client_id")
	return params
}

// TestConfidentialClientRotatesByDefault checks that a confidential Client's refresh token rotates unless the Authorization Server is configured to reuse it.
//
//conformance:covers INV-0004
func TestConfidentialClientRotatesByDefault(t *testing.T) {
	a := newConfidentialServer(t)
	a.wantReuseRevokesGrant(a.confidentialRefreshToken(), confidentialRefreshParams, basic(confidentialID, secret))
}

// TestConfidentialClientReusesRefreshToken checks that a confidential Client keeps its refresh token when the Authorization Server is configured to reuse it.
func TestConfidentialClientReusesRefreshToken(t *testing.T) {
	a := newReusingServer(t)
	refresh := a.confidentialRefreshToken()
	for range 2 {
		if _, next := a.tokens(confidentialRefreshParams(refresh), basic(confidentialID, secret)); next != "" {
			t.Fatalf("got refresh token %q, want none", next)
		}
	}
}

// TestPublicClientRotatesWhenConfidentialReuse checks that a public Client's refresh token rotates even when confidential Clients reuse theirs.
//
//conformance:covers INV-0004
func TestPublicClientRotatesWhenConfidentialReuse(t *testing.T) {
	a := newReusingServer(t)
	a.wantReuseRevokesGrant(a.publicRefreshToken(), refreshParams, nil)
}

// newReusingServer starts an Authorization Server with the confidential Client, on which confidential Clients reuse their refresh tokens.
func newReusingServer(t *testing.T) *authorizationServer {
	t.Helper()
	return newConfiguredServer(t, func(c *oauth21.Config) { c.ReuseConfidentialRefreshTokens = true }, confidentialClient(t))
}

// TestConfidentialRefreshRequiresAuthentication checks that a confidential Client must authenticate to refresh.
func TestConfidentialRefreshRequiresAuthentication(t *testing.T) {
	a := newConfidentialServer(t)
	params := confidentialRefreshParams(a.confidentialRefreshToken())
	params.Set("client_id", confidentialID)
	status, _, body := a.token(params, nil)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_client")
	status, _, body = a.token(params, basic(confidentialID, "wrong"))
	a.wantTokenError(status, body, http.StatusUnauthorized, "invalid_client")
}

// TestRefreshTokenIsBoundToClient checks that a refresh token issued to one Client cannot be used by another.
func TestRefreshTokenIsBoundToClient(t *testing.T) {
	a := newConfidentialServer(t)
	status, _, body := a.token(confidentialRefreshParams(a.publicRefreshToken()), basic(confidentialID, secret))
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
	status, _, body = a.token(refreshParams(a.confidentialRefreshToken()), nil)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestRefreshMayNarrowScopes checks that a refresh request may ask for fewer of the granted scopes, and that the next refresh token keeps all of them.
//
//conformance:covers INV-0003
func TestRefreshMayNarrowScopes(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("scope", "read write")
	_, refresh := a.tokens(tokenParams(a.code(params)), nil)
	narrow := refreshParams(refresh)
	narrow.Set("scope", "write")
	status, _, body := a.token(narrow, nil)
	if status != http.StatusOK || body["scope"] != "write" {
		t.Fatalf("got status %d and body %v, want scope write", status, body)
	}
	next, _ := body["refresh_token"].(string)
	if status, _, body := a.token(refreshParams(next), nil); status != http.StatusOK || body["scope"] != "read write" {
		t.Fatalf("got status %d and body %v, want scope read write", status, body)
	}
}

// TestRefreshCannotWidenScopes checks that a refresh request for a scope the Resource Owner did not grant fails with invalid_scope and keeps the refresh token.
//
//conformance:covers INV-0003
func TestRefreshCannotWidenScopes(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("scope", "read write")
	req := a.pending(a.authorize(params))
	u := a.complete(req.ID, oauth21.Completion{Subject: "alice", Scopes: readScope})
	_, refresh := a.tokens(tokenParams(u.Query().Get("code")), nil)
	wide := refreshParams(refresh)
	wide.Set("scope", "read write")
	status, _, body := a.token(wide, nil)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_scope")
	if _, next := a.tokens(refreshParams(refresh), nil); next == "" {
		t.Fatal("got no refresh token after a failed refresh")
	}
}

// TestRefreshTokenExpires checks that a Refresh Token Family expires as a whole, and that no access token outlives it.
func TestRefreshTokenExpires(t *testing.T) {
	a := newConfiguredServer(t, func(c *oauth21.Config) { c.RefreshTokenLifetime = 2 * time.Hour })
	refresh := a.publicRefreshToken()
	a.advance(90 * time.Minute)
	status, _, body := a.token(refreshParams(refresh), nil)
	if expires, _ := body["expires_in"].(float64); status != http.StatusOK || expires > 30*60 {
		t.Fatalf("got status %d and body %v, want an access token expiring with the refresh token", status, body)
	}
	next, _ := body["refresh_token"].(string)
	a.advance(30 * time.Minute)
	status, _, body = a.token(refreshParams(next), nil)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestRedeemedAccessTokenExpiresWithRefreshToken checks that the access token of a code redemption expires at the latest with its Refresh Token Family.
//
//conformance:covers INV-0004
func TestRedeemedAccessTokenExpiresWithRefreshToken(t *testing.T) {
	a := newConfiguredServer(t, func(c *oauth21.Config) { c.RefreshTokenLifetime = 30 * time.Minute })
	status, _, body := a.token(tokenParams(a.code(authorizeParams())), nil)
	if expires, _ := body["expires_in"].(float64); status != http.StatusOK || expires > 30*60 {
		t.Fatalf("got status %d and body %v, want an access token expiring with the refresh token", status, body)
	}
}

// TestCodeRedemptionWithoutRefreshGrant checks that a Client not allowed the refresh_token grant type gets no refresh token for its code.
func TestCodeRedemptionWithoutRefreshGrant(t *testing.T) {
	client := confidentialClient(t)
	client.GrantTypes = []string{"authorization_code"}
	a := newAuthorizationServer(t, client)
	if _, refresh := a.tokens(a.confidentialCode(), basic(confidentialID, secret)); refresh != "" {
		t.Fatal("got a refresh token, want none")
	}
}
