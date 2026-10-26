package conformance

import (
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/store"
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

// wantReuseRevokesGrant refreshes with token and checks that presenting token again fails and revokes its successor and the access token the refresh issued.
func (a *authorizationServer) wantReuseRevokesGrant(token string, request func(string) url.Values, header http.Header) {
	t := a.t
	t.Helper()
	access, successor := a.tokens(request(token), header)
	if successor == "" || successor == token {
		t.Fatalf("got refresh token %q, want a new one", successor)
	}
	status, _, body := a.token(request(token), header)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	status, _, body = a.token(request(successor), header)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	a.wantInactive(access)
}

// TestPublicClientRefreshes checks that a public Client gets a new access token and a new refresh token for its refresh token, and that the presented one no longer refreshes.
//
//conformance:covers OAUTH21D16-4.3-04
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
	status, _, body := a.token(refreshParams(first), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestRotatedRefreshTokenRevokesGrant checks that presenting a rotated refresh token fails and revokes the refresh token that replaced it.
//
//conformance:covers INV-0004
func TestRotatedRefreshTokenRevokesGrant(t *testing.T) {
	a := newIntrospectionServer(t)
	a.wantReuseRevokesGrant(a.publicRefreshToken(), refreshParams, nil)
}

// TestCodeReplayRevokesRefreshToken checks that a second redemption of a code revokes the refresh token issued from it.
//
//conformance:covers OAUTH21D16-4.1.3-07
func TestCodeReplayRevokesRefreshToken(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	_, refresh := a.tokens(params, nil)
	if status, _, _ := a.token(params, nil); status != http.StatusBadRequest {
		t.Fatalf("got status %d for a replay, want 400", status)
	}
	status, _, body := a.token(refreshParams(refresh), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
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
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
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
	a := newIntrospectionServer(t)
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

// newReusingServer starts an Authorization Server with the confidential Client and the Resource Server Client, on which confidential Clients reuse their refresh tokens.
func newReusingServer(t *testing.T) *authorizationServer {
	t.Helper()
	return newConfiguredServer(t, func(c *oauth21.Config) { c.ReuseConfidentialRefreshTokens = true }, newIntrospectionClients(t)...)
}

// TestConfidentialRefreshRequiresAuthentication checks that a confidential Client must authenticate to refresh.
func TestConfidentialRefreshRequiresAuthentication(t *testing.T) {
	a := newConfidentialServer(t)
	params := confidentialRefreshParams(a.confidentialRefreshToken())
	params.Set("client_id", confidentialID)
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
	status, _, body = a.token(params, basic(confidentialID, "wrong"))
	a.wantOAuthError(status, body, http.StatusUnauthorized, "invalid_client")
}

// TestRefreshTokenIsBoundToClient checks that a refresh token issued to one Client cannot be used by another.
//
//conformance:covers OAUTH21D16-4.3-03
func TestRefreshTokenIsBoundToClient(t *testing.T) {
	a := newConfidentialServer(t)
	status, _, body := a.token(confidentialRefreshParams(a.publicRefreshToken()), basic(confidentialID, secret))
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	status, _, body = a.token(refreshParams(a.confidentialRefreshToken()), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
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
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_scope")
	if _, next := a.tokens(refreshParams(refresh), nil); next == "" {
		t.Fatal("got no refresh token after a failed refresh")
	}
}

// TestRefreshTokenExpires checks that a Refresh Token Family expires as a whole, and that no access token outlives it.
//
//conformance:covers OAUTH21D16-4.3.3-04
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
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
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
//
//conformance:covers OAUTH21D16-3.2.3-09
func TestCodeRedemptionWithoutRefreshGrant(t *testing.T) {
	client := confidentialClient(t)
	client.GrantTypes = []string{"authorization_code"}
	a := newAuthorizationServer(t, client)
	if _, refresh := a.tokens(a.confidentialCode(), basic(confidentialID, secret)); refresh != "" {
		t.Fatal("got a refresh token, want none")
	}
}

// TestUnauthenticatedClientRefreshTokenIsSingleUse checks that a public Client's refresh token no longer refreshes once used, also when confidential Clients may reuse theirs.
//
//conformance:covers OAUTH21D16-2.4-07
func TestUnauthenticatedClientRefreshTokenIsSingleUse(t *testing.T) {
	a := newReusingServer(t)
	refresh := a.publicRefreshToken()
	a.tokens(refreshParams(refresh), nil)
	status, _, body := a.token(refreshParams(refresh), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestRefreshTokenReplayIsDetected checks that presenting a public Client's refresh token after two rotations fails and revokes the active refresh token.
//
//conformance:covers OAUTH21D16-4.3.1-06
func TestRefreshTokenReplayIsDetected(t *testing.T) {
	a := newAuthorizationServer(t)
	first := a.publicRefreshToken()
	second := a.refreshToken(refreshParams(first), nil)
	active := a.refreshToken(refreshParams(second), nil)
	status, _, body := a.token(refreshParams(first), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	status, _, body = a.token(refreshParams(active), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestRefreshKeepsClient checks that the access tokens from a refresh and from the refresh of its successor belong to the Client the refresh token was issued to.
//
//conformance:covers OAUTH21D16-4.3-02
func TestRefreshKeepsClient(t *testing.T) {
	a := newIntrospectionServer(t)
	for _, access := range a.successiveAccessTokens(a.confidentialRefreshToken(), confidentialRefreshParams, basic(confidentialID, secret)) {
		if body := a.introspect(access); body["client_id"] != confidentialID {
			t.Fatalf("got %v, want client_id %s", body, confidentialID)
		}
	}
}

// successiveAccessTokens refreshes refresh and then its successor with params and header, and returns the two access tokens.
func (a *authorizationServer) successiveAccessTokens(refresh string, params func(string) url.Values, header http.Header) []string {
	a.t.Helper()
	var access []string
	for range 2 {
		token, next := a.tokens(params(refresh), header)
		access = append(access, token)
		refresh = next
	}
	return access
}

// TestRefreshTokenOfAnotherPublicClient checks that a public Client cannot refresh with a refresh token issued to another public Client.
//
//conformance:covers OAUTH21D16-4.3.1-05
func TestRefreshTokenOfAnotherPublicClient(t *testing.T) {
	a := newAuthorizationServer(t, publicClient("other", redirectURI))
	params := refreshParams(a.publicRefreshToken())
	params.Set("client_id", "other")
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestRefreshScopeFollowsGrant checks that a refresh request for a scope the authorization request did not ask for fails with invalid_scope, and that one without scope gets the granted scope.
//
//conformance:covers OAUTH21D16-4.3.1-03
func TestRefreshScopeFollowsGrant(t *testing.T) {
	a := newAuthorizationServer(t)
	params := refreshParams(a.publicRefreshToken())
	params.Set("scope", "read write")
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_scope")
	granted := authorizeParams()
	granted.Set("scope", "read write")
	_, refresh := a.tokens(tokenParams(a.code(granted)), nil)
	if status, _, body := a.token(refreshParams(refresh), nil); status != http.StatusOK || body["scope"] != "read write" {
		t.Fatalf("got status %d and body %v, want scope read write", status, body)
	}
}

// TestRotatedRefreshTokenKeepsScope checks that the refresh token issued by a narrowed refresh keeps the scope of the presented one.
//
//conformance:covers OAUTH21D16-4.3.3-02
func TestRotatedRefreshTokenKeepsScope(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("scope", "read write")
	_, refresh := a.tokens(tokenParams(a.code(params)), nil)
	narrow := refreshParams(refresh)
	narrow.Set("scope", "read")
	_, next := a.tokens(narrow, nil)
	if _, _, body := a.token(refreshParams(next), nil); body["scope"] != "read write" {
		t.Fatalf("got body %v, want scope read write", body)
	}
}

// TestRefreshTokenIsBoundToGrantedScope checks that a refresh token cannot obtain a requested scope the Host Application did not grant.
//
//conformance:covers OAUTH21D16-3.2.3-11
func TestRefreshTokenIsBoundToGrantedScope(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("scope", "read write")
	req := a.pending(a.authorize(params))
	u := a.complete(req.ID, oauth21.Completion{Subject: "alice", Scopes: readScope})
	_, refresh := a.tokens(tokenParams(u.Query().Get("code")), nil)
	wide := refreshParams(refresh)
	wide.Set("scope", "write")
	status, _, body := a.token(wide, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_scope")
}

// TestUnknownRefreshTokenIsRejected checks that a refresh token the server did not issue gets invalid_grant.
//
//conformance:covers OAUTH21D16-4.3.1-09
func TestUnknownRefreshTokenIsRejected(t *testing.T) {
	a := newAuthorizationServer(t)
	status, _, body := a.token(refreshParams("unknown"), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestRefreshKeepsAudience checks that the access tokens from a refresh and from the refresh of its successor have the audience of the refresh token's Grant.
//
//conformance:covers OAUTH21D16-3.2.3-14
func TestRefreshKeepsAudience(t *testing.T) {
	a := newIntrospectionServer(t)
	refresh, hash := randomWithHash(t)
	if err := a.recorder.Store.CreateRefreshToken(t.Context(), store.RefreshToken{Hash: hash, Grant: aliceGrant("audience-grant", resourceServerID), ExpiresAt: a.now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, access := range a.successiveAccessTokens(refresh, refreshParams, nil) {
		if body := a.introspect(access); body["active"] != true || !reflect.DeepEqual(body["aud"], resourceServerID) && !reflect.DeepEqual(body["aud"], []any{resourceServerID}) {
			t.Fatalf("got %v, want an active token with audience %s", body, resourceServerID)
		}
	}
}

// TestPublicClientRefreshTokensRotate checks that every refresh of a public Client returns a new refresh token and retires the presented one, also where confidential Clients reuse theirs.
//
//conformance:covers RFC9700-2.2.2-01
func TestPublicClientRefreshTokensRotate(t *testing.T) {
	a := newReusingServer(t)
	tokens := []string{a.publicRefreshToken()}
	for range 3 {
		next := a.refreshToken(refreshParams(tokens[len(tokens)-1]), nil)
		if slices.Contains(tokens, next) {
			t.Fatalf("got refresh token %q again, want a new one", next)
		}
		tokens = append(tokens, next)
	}
	status, _, body := a.token(refreshParams(tokens[0]), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestRefreshTokensFollowClientPolicy checks that the same confidential Client gets a refresh token when its grant types list refresh_token, and none when they leave it out.
//
//conformance:covers RFC9700-4.14.2-01
func TestRefreshTokensFollowClientPolicy(t *testing.T) {
	for _, tt := range []struct {
		grantTypes []string
		want       bool
	}{{[]string{"authorization_code", "refresh_token"}, true}, {[]string{"authorization_code"}, false}} {
		client := confidentialClient(t)
		client.GrantTypes = tt.grantTypes
		a := newAuthorizationServer(t, client)
		if _, refresh := a.tokens(a.confidentialCode(), basic(confidentialID, secret)); (refresh != "") != tt.want {
			t.Fatalf("grant types %v: got refresh token %q, want one: %v", tt.grantTypes, refresh, tt.want)
		}
	}
}

// TestRefreshedAccessTokenHasConsentedScope checks that the access tokens a refresh token issues carry the scope the Resource Owner consented to, not the wider one the Client requested.
//
//conformance:covers RFC9700-4.14.2-03
func TestRefreshedAccessTokenHasConsentedScope(t *testing.T) {
	a := newIntrospectionServer(t)
	params := authorizeParams()
	params.Set("scope", "read write")
	req := a.pending(a.authorize(params))
	u := a.complete(req.ID, oauth21.Completion{Subject: "alice", Scopes: readScope})
	_, refresh := a.tokens(tokenParams(u.Query().Get("code")), nil)
	for _, access := range a.successiveAccessTokens(refresh, refreshParams, nil) {
		if body := a.introspect(access); body["active"] != true || body["scope"] != "read" {
			t.Fatalf("got %v, want an active token with scope read", body)
		}
	}
}

// TestPublicRefreshTokenReplayRevokesFamily checks that presenting a rotated refresh token of a public Client fails and revokes the refresh token and access token its successor issued.
//
//conformance:covers RFC9700-4.14.2-04
func TestPublicRefreshTokenReplayRevokesFamily(t *testing.T) {
	a := newIntrospectionServer(t)
	a.wantReuseRevokesGrant(a.publicRefreshToken(), refreshParams, nil)
}
