package conformance

import (
	"net/http"
	"testing"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/bearer"
)

// newPrivilegeServer starts an Authorization Server with the confidential Client, the Resource Server Client, which may introspect, and the service Client.
func newPrivilegeServer(t *testing.T) *authorizationServer {
	t.Helper()
	return newAuthorizationServer(t, append(newIntrospectionClients(t), serviceClient(t))...)
}

// wantScope checks that the access token introspects as active with scope want.
func (a *authorizationServer) wantScope(token, want string) {
	a.t.Helper()
	if body := a.introspect(token); body["active"] != true || body["scope"] != want {
		a.t.Fatalf("got %v, want an active token with scope %q", body, want)
	}
}

// actions serves a read and a write action, each guarded by the bearer middleware with v that requires its scope.
func (a *authorizationServer) actions(v bearer.Validator) {
	for _, action := range []string{"read", "write"} {
		a.mux.Handle("/"+action, bearer.Middleware(v, action)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	}
}

// wantAction checks that a request with the access token to action gets wantStatus.
func (a *authorizationServer) wantAction(token, action string, wantStatus int) {
	a.t.Helper()
	if status, header, _ := a.send(http.MethodGet, "/"+action, "", bearerHeader(token)); status != wantStatus {
		a.t.Fatalf("got status %d and WWW-Authenticate %q at %s, want %d", status, header.Get("WWW-Authenticate"), action, wantStatus)
	}
}

// TestClientGetsOnlyAllowedScopes checks that a Client gets no scope outside its allowed scopes, whether it asks in an authorization request or a client credentials request, or refreshes a Grant after the scope was taken from it.
//
//conformance:covers OAUTH21D16-7.9-01
func TestClientGetsOnlyAllowedScopes(t *testing.T) {
	a := newPrivilegeServer(t)
	params := authorizeParams()
	params.Set("scope", "read admin")
	a.wantAuthorizationError(a.errorRedirect(params), "invalid_scope", "scope")
	status, _, body := a.token(clientCredentialsParams("read admin"), basic(serviceID, secret))
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_scope")
	params.Set("scope", "read write")
	_, refresh := a.tokens(tokenParams(a.code(params)), nil)
	readOnly := publicClient(clientID, redirectURI)
	a.recorder.AddClient(readOnly)
	access, _ := a.tokens(refreshParams(refresh), nil)
	a.wantScope(access, "read")
}

// TestTokenIsRestrictedToGrantedScope checks that an access token is served only where its granted scope reaches, not where a scope the Client requested but the Resource Owner did not grant would.
//
//conformance:covers OAUTH21D16-7.1.2-01
func TestTokenIsRestrictedToGrantedScope(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.actions(v)
		params := authorizeParams()
		params.Set("scope", "read write")
		req := a.pending(a.authorize(params))
		u := a.complete(req.ID, oauth21.Completion{Subject: "alice", Scopes: []string{"write"}})
		access, _ := a.tokens(tokenParams(u.Query().Get("code")), nil)
		a.wantAction(access, "write", http.StatusOK)
		a.wantAction(access, "read", http.StatusForbidden)
	})
}

// TestTokenHasOnlyRequestedScopes checks that the access tokens of a code and of its refresh carry only the scopes the Client requested, not every scope the Client is allowed.
//
//conformance:covers OAUTH21D16-7.1.4-01
func TestTokenHasOnlyRequestedScopes(t *testing.T) {
	a := newPrivilegeServer(t)
	params := authorizeParams()
	params.Set("scope", "write")
	access, refresh := a.tokens(tokenParams(a.code(params)), nil)
	a.wantScope(access, "write")
	access, _ = a.tokens(refreshParams(refresh), nil)
	a.wantScope(access, "write")
}

// TestClientCredentialsTokenHasOnlyRequestedScope checks that the access token of a client credentials request carries only the requested scope, not every scope the Client is allowed.
//
//conformance:covers OAUTH21D16-7.3.2-04
func TestClientCredentialsTokenHasOnlyRequestedScope(t *testing.T) {
	a := newPrivilegeServer(t)
	access, _ := a.tokens(clientCredentialsParams("write"), basic(serviceID, secret))
	a.wantScope(access, "write")
}

// TestNarrowedRefreshTokenHasOnlyRequestedScope checks that the access token of a refresh that asks for fewer of the granted scopes carries only those.
//
//conformance:covers RFC9700-2.3-01
func TestNarrowedRefreshTokenHasOnlyRequestedScope(t *testing.T) {
	a := newPrivilegeServer(t)
	params := authorizeParams()
	params.Set("scope", "read write")
	_, refresh := a.tokens(tokenParams(a.code(params)), nil)
	narrow := refreshParams(refresh)
	narrow.Set("scope", "write")
	access, _ := a.tokens(narrow, nil)
	a.wantScope(access, "write")
}

// TestTokenIsRestrictedToActions checks that an access token with scope read is served by the read action of a Resource Server and refused by its write action.
//
//conformance:covers OAUTH21D16-7.1.4-05
func TestTokenIsRestrictedToActions(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.actions(v)
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.wantAction(access, "read", http.StatusOK)
		a.wantAction(access, "write", http.StatusForbidden)
	})
}

// TestClientCredentialsTokenIsRestrictedToActions checks that a client credentials access token with scope write is served by the write action of a Resource Server and refused by its read action.
//
//conformance:covers RFC9700-2.3-06
func TestClientCredentialsTokenIsRestrictedToActions(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.recorder.AddClient(serviceClient(t))
		a.actions(v)
		access, _ := a.tokens(clientCredentialsParams("write"), basic(serviceID, secret))
		a.wantAction(access, "write", http.StatusOK)
		a.wantAction(access, "read", http.StatusForbidden)
	})
}
