package conformance

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gofabrik/oauth21/store"
)

const resourceServerID = "Resource Server"

// newIntrospectionServer starts an Authorization Server with the confidential Client and the Resource Server Client, which may introspect.
func newIntrospectionServer(t *testing.T) *authorizationServer {
	t.Helper()
	return newAuthorizationServer(t, newIntrospectionClients(t)...)
}

// newIntrospectionClients returns the confidential Client and the Resource Server Client, which may introspect.
func newIntrospectionClients(t *testing.T) []store.Client {
	t.Helper()
	resourceServer := confidentialClient(t)
	resourceServer.ID = resourceServerID
	resourceServer.RedirectURIs = nil
	resourceServer.Introspect = true
	return []store.Client{confidentialClient(t), resourceServer}
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

// TestIntrospectionRequestErrors checks that an introspection request without a token or not sent with POST fails with invalid_request.
func TestIntrospectionRequestErrors(t *testing.T) {
	a := newIntrospectionServer(t)
	a.wantIntrospectionError(url.Values{}, basic(resourceServerID, secret), http.StatusBadRequest, "invalid_request")
	status, _, body := a.sendJSON(http.MethodGet, "/introspect?token=unknown", "", basic(resourceServerID, secret))
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}
