package conformance

import (
	"net/http"
	"slices"
	"testing"

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
	a.wantAuthorizationError(a.authorize(params), "invalid_scope", "scope")
}

// TestScopeMustBeSupportedAndAllowed checks that requesting a scope that is unsupported or not allowed for the Client fails with invalid_scope.
//
//conformance:covers INV-0003
func TestScopeMustBeSupportedAndAllowed(t *testing.T) {
	for name, scope := range map[string]string{"unsupported": "read delete", "not allowed": "read admin"} {
		t.Run(name, func(t *testing.T) {
			a := newAuthorizationServer(t)
			params := authorizeParams()
			params.Set("scope", scope)
			a.wantAuthorizationError(a.authorize(params), "invalid_scope", "scope")
		})
	}
}
