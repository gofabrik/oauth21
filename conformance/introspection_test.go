package conformance

import (
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofabrik/oauth21/store"
)

const resourceServerID = "Resource Server"

// otherResourceServerID identifies a Resource Server other than the Resource Server Client.
const otherResourceServerID = "Other Resource Server"

// newIntrospectionServer starts an Authorization Server with the confidential Client, the Resource Server Client and the other Resource Server, which may introspect.
func newIntrospectionServer(t *testing.T) *authorizationServer {
	t.Helper()
	return newAuthorizationServer(t, newIntrospectionClients(t)...)
}

// newIntrospectionClients returns the confidential Client, the Resource Server Client and the other Resource Server, which may introspect.
func newIntrospectionClients(t *testing.T) []store.Client {
	t.Helper()
	clients := []store.Client{confidentialClient(t)}
	for _, id := range []string{resourceServerID, otherResourceServerID} {
		resourceServer := confidentialClient(t)
		resourceServer.ID = id
		resourceServer.RedirectURIs = nil
		resourceServer.Introspect = true
		clients = append(clients, resourceServer)
	}
	return clients
}

// introspect sends an introspection request of the Resource Server Client for token that must succeed, and returns its decoded JSON body.
func (a *authorizationServer) introspect(token string) map[string]any {
	a.t.Helper()
	status, _, body := a.sendJSON(http.MethodPost, "/introspect", url.Values{"token": {token}}.Encode(), basic(resourceServerID, secret))
	if status != http.StatusOK {
		a.t.Fatalf("got status %d and body %v, want 200", status, body)
	}
	return body
}

// wantInactive checks that token introspects as inactive with no other details.
func (a *authorizationServer) wantInactive(token string) {
	a.t.Helper()
	if body := a.introspect(token); len(body) != 1 || body["active"] != false {
		a.t.Fatalf("got %v, want only active false", body)
	}
}

// wantIntrospectionError checks that an introspection request with header fails with wantStatus and code, and with a Basic challenge when the status is 401.
func (a *authorizationServer) wantIntrospectionError(params url.Values, header http.Header, wantStatus int, code string) {
	a.t.Helper()
	status, respHeader, body := a.sendJSON(http.MethodPost, "/introspect", params.Encode(), header)
	a.wantOAuthError(status, body, wantStatus, code)
	want := ""
	if status == http.StatusUnauthorized {
		want = `Basic realm="oauth21"`
	}
	if respHeader.Get("WWW-Authenticate") != want {
		a.t.Fatalf("got status %d and WWW-Authenticate %q, want %q", status, respHeader.Get("WWW-Authenticate"), want)
	}
}

// TestActiveAccessTokenIntrospection checks that an active access token introspects with its subject, Client, scopes and expiry.
func TestActiveAccessTokenIntrospection(t *testing.T) {
	a := newIntrospectionServer(t)
	before := a.now()
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	after := a.now()
	body := a.introspect(access)
	if body["active"] != true || body["sub"] != "alice" || body["client_id"] != clientID || body["scope"] != "read" {
		t.Fatalf("got %v, want an active token of alice and %s with scope read", body, clientID)
	}
	exp, ok := body["exp"].(float64)
	if !ok || int64(exp) < before.Add(time.Hour).Unix() || int64(exp) > after.Add(time.Hour).Unix() {
		t.Fatalf("got exp %v, want one hour after the token was issued", body["exp"])
	}
}

// TestInactiveTokenIntrospection checks that unknown, expired and revoked access tokens and refresh tokens introspect as inactive with no other details.
//
//conformance:covers RFC7662-2.2-19
func TestInactiveTokenIntrospection(t *testing.T) {
	t.Run("unknown", func(t *testing.T) {
		newIntrospectionServer(t).wantInactive("unknown")
	})
	t.Run("expired", func(t *testing.T) {
		a := newIntrospectionServer(t)
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.advance(time.Hour)
		a.wantInactive(access)
	})
	t.Run("revoked access token", func(t *testing.T) {
		a := newIntrospectionServer(t)
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.revoke(revocationParams(access), nil)
		a.wantInactive(access)
	})
	t.Run("access token of a revoked Grant", func(t *testing.T) {
		a := newIntrospectionServer(t)
		access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		refreshed, next := a.tokens(refreshParams(refresh), nil)
		a.revoke(revocationParams(next), nil)
		a.wantInactive(access)
		a.wantInactive(refreshed)
	})
	t.Run("refresh token", func(t *testing.T) {
		a := newIntrospectionServer(t)
		a.wantInactive(a.publicRefreshToken())
	})
}

// TestIntrospectionRequiresAuthorizedClient checks that only an authenticated confidential Client allowed to introspect can introspect, that invalid client credentials get 401, also without a token, and that more than one authentication method gets invalid_request.
func TestIntrospectionRequiresAuthorizedClient(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	token := url.Values{"token": {access}}
	a.wantIntrospectionError(token, nil, http.StatusUnauthorized, "invalid_client")
	a.wantIntrospectionError(url.Values{"token": {access}, "client_id": {clientID}}, nil, http.StatusUnauthorized, "invalid_client")
	a.wantIntrospectionError(url.Values{"token": {access}, "client_id": {resourceServerID}}, nil, http.StatusUnauthorized, "invalid_client")
	a.wantIntrospectionError(url.Values{"token": {access}, "client_id": {resourceServerID}, "client_secret": {"wrong"}}, nil, http.StatusUnauthorized, "invalid_client")
	a.wantIntrospectionError(token, basic(resourceServerID, "wrong"), http.StatusUnauthorized, "invalid_client")
	a.wantIntrospectionError(token, http.Header{"Authorization": {"Bearer " + access}}, http.StatusUnauthorized, "invalid_client")
	a.wantIntrospectionError(url.Values{}, basic(resourceServerID, "wrong"), http.StatusUnauthorized, "invalid_client")
	a.wantIntrospectionError(url.Values{"client_id": {resourceServerID}, "client_secret": {"wrong"}}, nil, http.StatusUnauthorized, "invalid_client")
	a.wantIntrospectionError(token, basic(confidentialID, secret), http.StatusBadRequest, "unauthorized_client")
	a.wantIntrospectionError(url.Values{"token": {access}, "client_secret": {secret}}, basic(resourceServerID, secret), http.StatusBadRequest, "invalid_request")
	status, _, body := a.sendJSON(http.MethodPost, "/introspect", url.Values{"token": {access}, "client_id": {resourceServerID}, "client_secret": {secret}}.Encode(), nil)
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("got status %d and body %v with client_secret_post, want an active token", status, body)
	}
}

// TestIntrospectionRequiresToken checks that an introspection request without a token fails with invalid_request.
//
//conformance:covers RFC7662-2.1-01
func TestIntrospectionRequiresToken(t *testing.T) {
	a := newIntrospectionServer(t)
	a.wantIntrospectionError(url.Values{}, basic(resourceServerID, secret), http.StatusBadRequest, "invalid_request")
	a.wantIntrospectionError(url.Values{"token": {""}}, basic(resourceServerID, secret), http.StatusBadRequest, "invalid_request")
}

// TestIntrospectionRequiresPost checks that an introspection request not sent with POST fails with invalid_request.
//
//conformance:covers RFC7662-4-14
func TestIntrospectionRequiresPost(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	status, _, body := a.sendJSON(http.MethodGet, "/introspect?"+url.Values{"token": {access}}.Encode(), "", basic(resourceServerID, secret))
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestOnlyAuthorizedClientsIntrospectAccessTokens checks that a Client not allowed to introspect learns nothing about an access token issued to another Client: it gets the same error for that token as for an unknown one.
//
//conformance:covers OAUTH21D16-1.4-05
func TestOnlyAuthorizedClientsIntrospectAccessTokens(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	var bodies []map[string]any
	for _, token := range []string{access, "unknown"} {
		status, _, body := a.sendJSON(http.MethodPost, "/introspect", url.Values{"token": {token}}.Encode(), basic(confidentialID, secret))
		a.wantOAuthError(status, body, http.StatusBadRequest, "unauthorized_client")
		if len(body) != 2 || body["error_description"] == nil {
			t.Fatalf("got body %v, want only error and error_description", body)
		}
		bodies = append(bodies, body)
	}
	if !maps.Equal(bodies[0], bodies[1]) {
		t.Fatalf("got %v for the access token and %v for an unknown token, want the same", bodies[0], bodies[1])
	}
}

// TestRefreshTokenIsNotIntrospected checks that the Resource Server Client gets a refresh token only as inactive, while the refresh token still refreshes.
//
//conformance:covers OAUTH21D16-4.3-07
func TestRefreshTokenIsNotIntrospected(t *testing.T) {
	a := newIntrospectionServer(t)
	refresh := a.publicRefreshToken()
	a.wantInactive(refresh)
	a.tokens(refreshParams(refresh), nil)
}

// introspectWith sends an introspection request for token with header and params and returns its status and decoded JSON body.
func (a *authorizationServer) introspectWith(token string, params url.Values, header http.Header) (int, map[string]any) {
	a.t.Helper()
	form := url.Values{"token": {token}}
	maps.Copy(form, params)
	status, _, body := a.sendJSON(http.MethodPost, "/introspect", form.Encode(), header)
	return status, body
}

// wantActive checks that token introspects as active.
func (a *authorizationServer) wantActive(token string) {
	a.t.Helper()
	if body := a.introspect(token); body["active"] != true {
		a.t.Fatalf("got %v, want an active token", body)
	}
}

// TestIntrospectionSearchesBeyondHint checks that an active access token introspects as active whatever token_type_hint names.
//
//conformance:covers RFC7662-2.1-04
func TestIntrospectionSearchesBeyondHint(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	for _, hint := range []string{"access_token", "refresh_token", "unknown"} {
		status, body := a.introspectWith(access, url.Values{"token_type_hint": {hint}}, basic(resourceServerID, secret))
		if status != http.StatusOK || body["active"] != true {
			t.Fatalf("got status %d and body %v with hint %s, want an active token", status, body, hint)
		}
	}
}

// TestIntrospectionRequiresAuthorization checks that a request without client authentication, also one carrying the access token as a bearer token, is refused and learns nothing about the token.
//
//conformance:covers RFC7662-2.1-09
func TestIntrospectionRequiresAuthorization(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	for _, header := range []http.Header{nil, bearerHeader(access)} {
		status, body := a.introspectWith(access, nil, header)
		a.wantOAuthError(status, body, http.StatusUnauthorized, "invalid_client")
		if _, ok := body["active"]; ok {
			t.Fatalf("got body %v, want no active member", body)
		}
	}
}

// TestIntrospectionResponseHasActive checks that the introspection responses for an active and an inactive token carry active as a boolean.
//
//conformance:covers RFC7662-2.2-01
func TestIntrospectionResponseHasActive(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	for token, want := range map[string]bool{access: true, "unknown": false} {
		if body := a.introspect(token); body["active"] != want {
			t.Fatalf("got %v, want active %v", body, want)
		}
	}
}

// introspectionNames are the names of the initial OAuth Token Introspection Response registry (RFC 7662 3.2).
var introspectionNames = []string{"active", "username", "client_id", "scope", "token_type", "exp", "iat", "nbf", "sub", "aud", "iss", "jti"}

// TestIntrospectionResponseNamesAreRegistered checks that the introspection response of an active token with an audience uses only registered names.
//
//conformance:covers RFC7662-2.2-14
func TestIntrospectionResponseNamesAreRegistered(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	for _, token := range []string{access, a.audienceToken(resourceServerID)} {
		body := a.introspect(token)
		for name := range body {
			if !slices.Contains(introspectionNames, name) {
				t.Fatalf("got member %q in %v, want only registered names", name, body)
			}
		}
	}
}

// TestNotActiveTokenIntrospectsInactive checks that an expired and a revoked access token get a response with active false.
//
//conformance:covers RFC7662-2.2-18
func TestNotActiveTokenIntrospectsInactive(t *testing.T) {
	a := newIntrospectionServer(t)
	revoked, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.revoke(revocationParams(revoked), nil)
	if body := a.introspect(revoked); body["active"] != false {
		t.Fatalf("got %v for a revoked token, want active false", body)
	}
	expired, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.advance(time.Hour)
	if body := a.introspect(expired); body["active"] != false {
		t.Fatalf("got %v for an expired token, want active false", body)
	}
}

// TestUnknownTokenIntrospectsInactive checks that a token the server never issued, also one of the form of its tokens, gets a response with active false.
//
//conformance:covers RFC7662-2.2-20
func TestUnknownTokenIntrospectsInactive(t *testing.T) {
	a := newIntrospectionServer(t)
	for _, token := range []string{"unknown", random(t)} {
		if body := a.introspect(token); body["active"] != false {
			t.Fatalf("got %v, want active false", body)
		}
	}
}

// TestTokenForOtherResourceServerIntrospectsInactive checks that an access token whose audience names only other Resource Servers gets a response with active false.
//
//conformance:covers RFC7662-2.2-21
func TestTokenForOtherResourceServerIntrospectsInactive(t *testing.T) {
	a := newIntrospectionServer(t)
	for _, audience := range otherAudiences {
		if body := a.introspect(a.audienceToken(audience...)); body["active"] != false {
			t.Fatalf("got %v for audience %q, want active false", body, audience)
		}
	}
}

// TestInactiveTokenIsNoError checks that an authorized request for an unknown, expired, revoked or foreign token gets a 200 introspection response, not an error.
//
//conformance:covers RFC7662-2.3-01
func TestInactiveTokenIsNoError(t *testing.T) {
	a := newIntrospectionServer(t)
	wantNoError := func(token string) {
		t.Helper()
		status, body := a.introspectWith(token, nil, basic(resourceServerID, secret))
		if _, isError := body["error"]; status != http.StatusOK || isError || body["active"] != false {
			t.Fatalf("got status %d and body %v, want 200 with active false", status, body)
		}
	}
	revoked, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.revoke(revocationParams(revoked), nil)
	for _, token := range []string{"unknown", revoked, a.audienceToken("other"), a.publicRefreshToken()} {
		wantNoError(token)
	}
	expired, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.advance(time.Hour)
	wantNoError(expired)
}

// TestIntrospectionChecksTokenState checks that an access token introspects as active only while it is unexpired, unrevoked, of a live Grant and meant for the Resource Server.
func TestIntrospectionChecksTokenState(t *testing.T) {
	a := newIntrospectionServer(t)
	live, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	revoked, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.revoke(revocationParams(revoked), nil)
	ofRevokedGrant, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.revoke(revocationParams(refresh), nil)
	a.wantActive(live)
	a.wantActive(a.audienceToken(resourceServerID))
	for _, token := range []string{revoked, ofRevokedGrant, a.audienceToken("other")} {
		a.wantInactive(token)
	}
	a.advance(time.Hour)
	a.wantInactive(live)
}

// TestIntrospectionChecksExpiry checks that an access token introspects as active until its expiry and as inactive from then on.
//
//conformance:covers RFC7662-4-02
func TestIntrospectionChecksExpiry(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.advance(time.Hour - time.Second)
	a.wantActive(access)
	a.advance(time.Second)
	a.wantInactive(access)
}

// TestIntrospectionChecksRevocation checks that a revoked access token and the access tokens of a revoked Grant introspect as inactive.
//
//conformance:covers RFC7662-4-04
func TestIntrospectionChecksRevocation(t *testing.T) {
	a := newIntrospectionServer(t)
	revoked, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.wantActive(revoked)
	a.revoke(revocationParams(revoked), nil)
	a.wantInactive(revoked)
	access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.wantActive(access)
	a.revoke(revocationParams(refresh), nil)
	a.wantInactive(access)
}

// TestIntrospectionChecksAudience checks that an access token introspects as active for a Resource Server its audience names, alone or with others, and as inactive when it names only others.
//
//conformance:covers RFC7662-4-06
func TestIntrospectionChecksAudience(t *testing.T) {
	a := newIntrospectionServer(t)
	a.wantActive(a.audienceToken(resourceServerID))
	a.wantActive(a.audienceToken("other", resourceServerID))
	a.wantInactive(a.audienceToken("other"))
}

// TestIntrospectionRequiresAuthentication checks that a Resource Server allowed to introspect must authenticate: no credentials, its client_id alone or a wrong secret get 401.
//
//conformance:covers RFC7662-4-07
func TestIntrospectionRequiresAuthentication(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	for _, c := range []struct {
		params url.Values
		header http.Header
	}{
		{nil, nil},
		{url.Values{"client_id": {resourceServerID}}, nil},
		{url.Values{"client_id": {resourceServerID}, "client_secret": {"wrong"}}, nil},
		{nil, basic(resourceServerID, "wrong")},
	} {
		status, body := a.introspectWith(access, c.params, c.header)
		a.wantOAuthError(status, body, http.StatusUnauthorized, "invalid_client")
	}
}

// TestIntrospectionRequiresPermission checks that an authenticated confidential Client not allowed to introspect gets unauthorized_client.
//
//conformance:covers RFC7662-4-08
func TestIntrospectionRequiresPermission(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	status, body := a.introspectWith(access, nil, basic(confidentialID, secret))
	a.wantOAuthError(status, body, http.StatusBadRequest, "unauthorized_client")
}

// TestIntrospectionDisclosesSubjectOnlyToResourceServer checks that the subject of an access token reaches only the authenticated Resource Server allowed to introspect, never an unauthenticated caller or another Client.
//
//conformance:covers RFC7662-5-01
func TestIntrospectionDisclosesSubjectOnlyToResourceServer(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	if body := a.introspect(access); body["sub"] != "alice" {
		t.Fatalf("got %v, want the subject alice", body)
	}
	for _, header := range []http.Header{nil, basic(confidentialID, secret), basic(resourceServerID, "wrong")} {
		_, _, raw := a.send(http.MethodPost, "/introspect", url.Values{"token": {access}}.Encode(), header)
		if strings.Contains(string(raw), "alice") {
			t.Fatalf("got body %s, want no subject", raw)
		}
	}
}

// TestInactiveTokenHasOnlyActive checks that the introspection responses for an unknown, an expired, a revoked and a foreign token carry only active.
//
//conformance:covers RFC7662-4-15
func TestInactiveTokenHasOnlyActive(t *testing.T) {
	a := newIntrospectionServer(t)
	revoked, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.revoke(revocationParams(revoked), nil)
	for _, token := range []string{"unknown", revoked, a.audienceToken("other")} {
		a.wantInactive(token)
	}
	expired, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.advance(time.Hour)
	a.wantInactive(expired)
}
