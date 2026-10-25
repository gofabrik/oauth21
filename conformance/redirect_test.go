package conformance

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/gofabrik/oauth21/store"
)

// TestLoopbackRedirectURIIgnoresPort checks that loopback IP redirect URIs match with any port.
//
//conformance:covers OAUTH21D16-8.4.2-02
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
//
//conformance:covers OAUTH21D16-2.3.1-02
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
			if status, loc := a.sendAuthorization(params); status != http.StatusBadRequest || loc != "" {
				t.Fatalf("got status %d and Location %q, want 400 without redirect", status, loc)
			}
		})
	}
}

// TestCodeIsBoundToClient checks that another Client cannot redeem a code.
//
//conformance:covers OAUTH21D16-4.1.3-08
func TestCodeIsBoundToClient(t *testing.T) {
	a := newAuthorizationServer(t, store.Client{ID: "other", Type: store.Public, RedirectURIs: []string{redirectURI}, AllowedScopes: readScope, DefaultScopes: readScope})
	params := tokenParams(a.code(authorizeParams()))
	params.Set("client_id", "other")
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// sendAuthorization sends the authorization request params and returns the status and Location of the response.
func (a *authorizationServer) sendAuthorization(params url.Values) (int, string) {
	a.t.Helper()
	status, header, _ := a.send(http.MethodGet, "/authorize?"+params.Encode(), "", nil)
	return status, header.Get("Location")
}

// withRedirectURI returns a valid authorization request of the public Client for uri.
func withRedirectURI(uri string) url.Values {
	params := authorizeParams()
	params.Set("redirect_uri", uri)
	return params
}

// TestRedirectURIMustBeComplete checks that a redirect URI extending the registered path is not redirected to.
//
//conformance:covers OAUTH21D16-2.3.1-01
func TestRedirectURIMustBeComplete(t *testing.T) {
	a := newAuthorizationServer(t)
	if _, loc := a.sendAuthorization(withRedirectURI(redirectURI + "/deeper")); loc != "" {
		t.Fatalf("got Location %q, want no redirect", loc)
	}
}

// TestMismatchingRedirectURIIsNotRedirected checks that the user agent is not redirected to a redirect URI the Client did not register.
//
//conformance:covers OAUTH21D16-2.3.5-02
func TestMismatchingRedirectURIIsNotRedirected(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, uri := range []string{"https://attacker.example/cb", "://invalid"} {
		if _, loc := a.sendAuthorization(withRedirectURI(uri)); loc != "" {
			t.Fatalf("%s: got Location %q, want no redirect", uri, loc)
		}
	}
}

// TestRedirectURIMustBeRegistered checks that a redirect_uri is accepted only when it is one of the registered redirect URIs.
//
//conformance:covers OAUTH21D16-4.1.1-19
func TestRedirectURIMustBeRegistered(t *testing.T) {
	other := "https://client.example/other"
	a := newAuthorizationServer(t, store.Client{ID: "two", Type: store.Public, RedirectURIs: []string{redirectURI, other}, AllowedScopes: readScope, DefaultScopes: readScope})
	params := withRedirectURI(other)
	params.Set("client_id", "two")
	if u := a.login(a.authorize(params), "alice"); endpoint(u) != other {
		t.Fatalf("got redirect %s, want %s", u, other)
	}
	if _, loc := a.sendAuthorization(withRedirectURI(other)); loc != "" {
		t.Fatalf("got Location %q for a redirect URI of another Client, want no redirect", loc)
	}
}

// TestRedirectURIIsComparedAsString checks that redirect URIs equivalent to the registered one but spelled differently are not redirected to.
//
//conformance:covers OAUTH21D16-4.1.1-20
func TestRedirectURIIsComparedAsString(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, uri := range []string{"https://CLIENT.example/cb", "HTTPS://client.example/cb", "https://client.example:443/cb", "https://client.example/%63b"} {
		if _, loc := a.sendAuthorization(withRedirectURI(uri)); loc != "" {
			t.Fatalf("%s: got Location %q, want no redirect", uri, loc)
		}
	}
}

// TestInvalidClientIsNotRedirected checks that a request with a missing or unknown client_id is not redirected.
//
//conformance:covers OAUTH21D16-4.1.2.1-01
func TestInvalidClientIsNotRedirected(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, id := range []string{"", "unknown"} {
		params := authorizeParams()
		params.Set("client_id", id)
		if _, loc := a.sendAuthorization(params); loc != "" {
			t.Fatalf("client_id %q: got Location %q, want no redirect", id, loc)
		}
	}
}

// TestDirectErrorIsBadRequest checks that an error shown to the user agent instead of redirected has status 400.
//
//conformance:covers OAUTH21D16-4.1.2.1-03
func TestDirectErrorIsBadRequest(t *testing.T) {
	a := newAuthorizationServer(t)
	if status, _ := a.sendAuthorization(withRedirectURI("https://attacker.example/cb")); status != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", status)
	}
}

// TestRedirectURIIsValidatedBeforeErrors checks that a request with an unregistered redirect URI and other errors is not redirected.
//
//conformance:covers OAUTH21D16-4.1.2.1-04
func TestRedirectURIIsValidatedBeforeErrors(t *testing.T) {
	a := newAuthorizationServer(t)
	params := withRedirectURI("https://attacker.example/cb")
	params.Set("response_type", "token")
	params.Del("code_challenge")
	params.Set("scope", "delete")
	if _, loc := a.sendAuthorization(params); loc != "" {
		t.Fatalf("got Location %q, want no redirect", loc)
	}
}

// TestLoopbackRedirectURIAllowsVariablePort checks that a loopback redirect URI registered with a port matches a request with another port.
//
//conformance:covers OAUTH21D16-4.1.1-21
func TestLoopbackRedirectURIAllowsVariablePort(t *testing.T) {
	a := newAuthorizationServer(t, store.Client{ID: "native", Type: store.Public, RedirectURIs: []string{"http://[::1]:8080/cb"}, AllowedScopes: readScope, DefaultScopes: readScope})
	params := withRedirectURI("http://[::1]:49152/cb")
	params.Set("client_id", "native")
	if u := a.login(a.authorize(params), "alice"); endpoint(u) != "http://[::1]:49152/cb" {
		t.Fatalf("got redirect %s, want http://[::1]:49152/cb", u)
	}
}

// TestRedirectURIQueryIsKept checks that the authorization response keeps the query of the registered redirect URI.
//
//conformance:covers OAUTH21D16-2.3-03
func TestRedirectURIQueryIsKept(t *testing.T) {
	uri := redirectURI + "?tenant=a"
	a := newAuthorizationServer(t, store.Client{ID: "tenant", Type: store.Public, RedirectURIs: []string{uri}, AllowedScopes: readScope, DefaultScopes: readScope})
	params := withRedirectURI(uri)
	params.Set("client_id", "tenant")
	u := a.login(a.authorize(params), "alice")
	if q := u.Query(); endpoint(u) != redirectURI || q.Get("tenant") != "a" || q.Get("code") == "" {
		t.Fatalf("got redirect %s, want tenant=a and a code", u)
	}
}
