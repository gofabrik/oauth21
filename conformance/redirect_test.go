package conformance

import (
	"net/http"
	"testing"

	"github.com/gofabrik/oauth21/store"
)

// TestLoopbackRedirectURIIgnoresPort checks that loopback IP redirect URIs match with any port.
func TestLoopbackRedirectURIIgnoresPort(t *testing.T) {
	for registered, requested := range map[string]string{
		"http://127.0.0.1/cb":      "http://127.0.0.1:51004/cb",
		"http://127.0.0.1:8080/cb": "http://127.0.0.1:51004/cb",
		"http://[::1]/cb":          "http://[::1]:61023/cb",
	} {
		t.Run(requested, func(t *testing.T) {
			a := newAuthorizationServer(t, store.Client{ID: "native", Type: store.Public, RedirectURIs: []string{registered}, AllowedScopes: readScope, DefaultScopes: readScope})
			params := authorizeParams()
			params.Set("client_id", "native")
			params.Set("redirect_uri", requested)
			u := a.login(a.authorize(params), "alice")
			if got := endpoint(u); got != requested || u.Query().Get("code") == "" {
				t.Fatalf("got redirect %s, want a code at %s", u, requested)
			}
		})
	}
}

// TestRedirectURIMustMatchExactly checks that an unregistered redirect URI or unknown Client is not redirected to.
func TestRedirectURIMustMatchExactly(t *testing.T) {
	tests := map[string]struct{ clientID, redirectURI string }{
		"unknown client":   {"unknown", redirectURI},
		"other path":       {clientID, redirectURI + "/other"},
		"query added":      {clientID, redirectURI + "?x=1"},
		"port added":       {clientID, "https://client.example:443/cb"},
		"trailing slash":   {clientID, redirectURI + "/"},
		"localhost":        {"localhost", "http://localhost:51004/cb"},
		"loopback scheme":  {"native", "https://127.0.0.1:51004/cb"},
		"loopback path":    {"native", "http://127.0.0.1:51004/other"},
		"non-loopback ip":  {"lan", "http://10.0.0.1:51004/cb"},
		"loopback as host": {"native", "http://127.0.0.1.example:51004/cb"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := newAuthorizationServer(t,
				store.Client{ID: "native", Type: store.Public, RedirectURIs: []string{"http://127.0.0.1/cb"}, AllowedScopes: readScope, DefaultScopes: readScope},
				store.Client{ID: "localhost", Type: store.Public, RedirectURIs: []string{"http://localhost/cb"}, AllowedScopes: readScope, DefaultScopes: readScope},
				store.Client{ID: "lan", Type: store.Public, RedirectURIs: []string{"http://10.0.0.1/cb"}, AllowedScopes: readScope, DefaultScopes: readScope},
			)
			params := authorizeParams()
			params.Set("client_id", tt.clientID)
			params.Set("redirect_uri", tt.redirectURI)
			status, header, _ := a.send(http.MethodGet, "/authorize?"+params.Encode(), "", nil)
			if status != http.StatusBadRequest || header.Get("Location") != "" {
				t.Fatalf("got status %d and Location %q, want 400 without redirect", status, header.Get("Location"))
			}
		})
	}
}

// TestCodeIsBoundToClient checks that another Client cannot redeem a code.
func TestCodeIsBoundToClient(t *testing.T) {
	a := newAuthorizationServer(t, store.Client{ID: "other", Type: store.Public, RedirectURIs: []string{redirectURI}, AllowedScopes: readScope, DefaultScopes: readScope})
	params := tokenParams(a.code(authorizeParams()))
	params.Set("client_id", "other")
	status, _, body := a.token(params, nil)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
}
