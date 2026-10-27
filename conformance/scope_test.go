package conformance

import (
	"net/http"
	"slices"
	"testing"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/store"
)

// TestRequestWithoutScopeGetsDefaultScopes checks that a request without scope asks for the Client's default scopes and the token response names them.
//
//conformance:covers INV-0003
func TestRequestWithoutScopeGetsDefaultScopes(t *testing.T) {
	a := newAuthorizationServer(t)
	loc := a.authorize(authorizeParams())
	if req := a.pending(loc); !slices.Equal(req.Scopes, readScope) {
		t.Fatalf("got requested scopes %q, want %q", req.Scopes, readScope)
	}
	status, _, body := a.token(tokenParams(a.login(loc, "alice").Query().Get("code")), nil)
	if status != http.StatusOK || body["scope"] != "read" {
		t.Fatalf("got status %d and body %v, want scope read", status, body)
	}
}

// TestRequestWithoutScopeOrDefaultsFails checks that a request without scope fails with invalid_scope for a Client without default scopes.
//
//conformance:covers INV-0003
func TestRequestWithoutScopeOrDefaultsFails(t *testing.T) {
	a := newAuthorizationServer(t, store.Client{ID: "nodefaults", Type: store.Public, RedirectURIs: []string{redirectURI}, AllowedScopes: readScope})
	params := authorizeParams()
	params.Set("client_id", "nodefaults")
	a.wantAuthorizationError(a.errorRedirect(params), "invalid_scope", "scope")
}

// TestScopeMustBeSupportedAndAllowed checks that requesting a scope that is unsupported though allowed for the Client, or supported but not allowed for it, fails with invalid_scope.
//
//conformance:covers INV-0003
func TestScopeMustBeSupportedAndAllowed(t *testing.T) {
	for name, scope := range map[string]string{"unsupported": "read delete", "not allowed": "read admin"} {
		t.Run(name, func(t *testing.T) {
			deleter := publicClient("deleter", redirectURI)
			deleter.AllowedScopes = []string{"read", "delete"}
			a := newAuthorizationServer(t, deleter)
			params := authorizeParams()
			params.Set("client_id", "deleter")
			params.Set("scope", scope)
			a.wantAuthorizationError(a.errorRedirect(params), "invalid_scope", "scope")
		})
	}
}

// TestTokenResponseNamesNarrowedScope checks that the token response names the scope when the Host Application grants less than requested.
//
//conformance:covers OAUTH21D16-1.4.1-02
func TestTokenResponseNamesNarrowedScope(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("scope", "read write")
	req := a.pending(a.authorize(params))
	u := a.complete(req.ID, oauth21.Completion{Subject: "alice", Scopes: []string{"write"}})
	status, _, body := a.token(tokenParams(u.Query().Get("code")), nil)
	if status != http.StatusOK || body["scope"] != "write" {
		t.Fatalf("got status %d and body %v, want scope write", status, body)
	}
}

// TestRequestWithoutScopeUsesDefaultOrFails checks that a request without scope gets the Client's default scopes, or invalid_scope when it has none.
//
//conformance:covers OAUTH21D16-1.4.1-03
func TestRequestWithoutScopeUsesDefaultOrFails(t *testing.T) {
	a := newAuthorizationServer(t, store.Client{ID: "nodefaults", Type: store.Public, RedirectURIs: []string{redirectURI}, AllowedScopes: readScope})
	if req := a.pending(a.authorize(authorizeParams())); !slices.Equal(req.Scopes, readScope) {
		t.Fatalf("got requested scopes %q, want the default scopes %q", req.Scopes, readScope)
	}
	params := authorizeParams()
	params.Set("client_id", "nodefaults")
	if q := a.errorRedirect(params).Query(); q.Get("error") != "invalid_scope" {
		t.Fatalf("got %v, want error invalid_scope", q)
	}
}

// TestTokenResponseNamesRequestedScope checks that the token response names the scope also when it is the requested one.
//
//conformance:covers OAUTH21D16-3.2.3-06
func TestTokenResponseNamesRequestedScope(t *testing.T) {
	a := newServiceServer(t)
	if _, _, body := a.token(clientCredentialsParams("write"), basic(serviceID, secret)); body["scope"] != "write" {
		t.Fatalf("got body %v, want scope write", body)
	}
}

// TestTokenResponseNamesDefaultScope checks that the token response of a request without scope names the default scopes it got.
//
//conformance:covers OAUTH21D16-3.2.3-07
func TestTokenResponseNamesDefaultScope(t *testing.T) {
	a := newServiceServer(t)
	if _, _, body := a.token(clientCredentialsParams(""), basic(serviceID, secret)); body["scope"] != "read" {
		t.Fatalf("got body %v, want scope read", body)
	}
}

// TestAllowedScopesDependOnClient checks that a scope one Client may obtain is refused to a Client not allowed it.
//
//conformance:covers OAUTH21D16-7.3.2-02
func TestAllowedScopesDependOnClient(t *testing.T) {
	a := newAuthorizationServer(t, publicClient("reader", redirectURI))
	params := authorizeParams()
	params.Set("scope", "write")
	if req := a.pending(a.authorize(params)); !slices.Equal(req.Scopes, []string{"write"}) {
		t.Fatalf("got requested scopes %q, want write", req.Scopes)
	}
	params.Set("client_id", "reader")
	if q := a.errorRedirect(params).Query(); q.Get("error") != "invalid_scope" {
		t.Fatalf("got %v, want error invalid_scope", q)
	}
}
