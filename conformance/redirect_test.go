package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gofabrik/oauth21/store"
)

// TestLoopbackRedirectURIIgnoresPort checks that loopback IP redirect URIs match with any port.
//
//conformance:covers OAUTH21D16-8.4.2-02
func TestLoopbackRedirectURIIgnoresPort(t *testing.T) {
	for requested, registered := range map[string]string{
		"http://127.0.0.1:51004/cb": "http://127.0.0.1/cb",
		"http://127.0.0.1:1024/cb":  "http://127.0.0.1:8080/cb",
		"http://127.0.0.1:8081/cb":  "http://127.0.0.1/cb",
		"http://127.0.0.1/cb":       "http://127.0.0.1:8080/cb",
		"http://[::1]:61023/cb":     "http://[::1]/cb",
		"http://[::1]:8081/cb":      "http://[::1]:8080/cb",
	} {
		t.Run(requested, func(t *testing.T) {
			a := newAuthorizationServer(t, publicClient(nativeID, registered))
			params := authorizeParams()
			params.Set("client_id", nativeID)
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
		"loopback scheme":  {nativeID, "https://127.0.0.1:51004/cb"},
		"loopback path":    {nativeID, "http://127.0.0.1:51004/other"},
		"loopback as host": {nativeID, "http://127.0.0.1.example:51004/cb"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := newAuthorizationServer(t, publicClient(nativeID, nativeRedirectURI))
			params := authorizeParams()
			params.Set("client_id", tt.clientID)
			params.Set("redirect_uri", tt.redirectURI)
			a.wantNoRedirect(params)
		})
	}
}

// TestCodeIsBoundToClient checks that another Client cannot redeem a code.
//
//conformance:covers OAUTH21D16-4.1.3-08
func TestCodeIsBoundToClient(t *testing.T) {
	a := newAuthorizationServer(t, publicClient("other", redirectURI))
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

// wantNoRedirect checks that the server refuses the authorization request params with a 400 and no redirect.
func (a *authorizationServer) wantNoRedirect(params url.Values) {
	a.t.Helper()
	if status, loc := a.sendAuthorization(params); status != http.StatusBadRequest || loc != "" {
		a.t.Fatalf("%s: got status %d and Location %q, want 400 without redirect", params.Encode(), status, loc)
	}
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
	a := newAuthorizationServer(t, publicClient("two", redirectURI, other))
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

// unredirectable returns authorization requests whose errors the server cannot redirect: one with an unregistered redirect URI and one of an unknown Client.
func unredirectable() map[string]url.Values {
	unknown := authorizeParams()
	unknown.Set("client_id", "unknown")
	return map[string]url.Values{"unregistered redirect URI": withRedirectURI("https://attacker.example/cb"), "unknown client": unknown}
}

// TestDirectErrorIsBadRequest checks that an error shown to the user agent instead of redirected has status 400, for an unregistered redirect URI and an unknown Client.
//
//conformance:covers OAUTH21D16-4.1.2.1-03
func TestDirectErrorIsBadRequest(t *testing.T) {
	a := newAuthorizationServer(t)
	for name, params := range unredirectable() {
		if status, _ := a.sendAuthorization(params); status != http.StatusBadRequest {
			t.Fatalf("%s: got status %d, want 400", name, status)
		}
	}
}

// TestRedirectURIIsValidatedBeforeErrors checks that a request with an unregistered redirect URI or an unknown Client and other errors is not redirected.
//
//conformance:covers OAUTH21D16-4.1.2.1-04
func TestRedirectURIIsValidatedBeforeErrors(t *testing.T) {
	a := newAuthorizationServer(t)
	for name, params := range unredirectable() {
		params.Set("response_type", "token")
		params.Del("code_challenge")
		params.Set("scope", "delete")
		if _, loc := a.sendAuthorization(params); loc != "" {
			t.Fatalf("%s: got Location %q, want no redirect", name, loc)
		}
	}
}

// TestLoopbackRedirectURIAllowsVariablePort checks that a loopback redirect URI registered with a port matches a request with another port or none.
//
//conformance:covers OAUTH21D16-4.1.1-21
func TestLoopbackRedirectURIAllowsVariablePort(t *testing.T) {
	a := newAuthorizationServer(t, publicClient(nativeID, "http://[::1]:8080/cb"))
	for _, uri := range []string{"http://[::1]:49152/cb", "http://[::1]:1024/cb", "http://[::1]:8081/cb", "http://[::1]/cb"} {
		params := withRedirectURI(uri)
		params.Set("client_id", nativeID)
		if u := a.login(a.authorize(params), "alice"); endpoint(u) != uri {
			t.Fatalf("got redirect %s, want %s", u, uri)
		}
	}
}

// TestRedirectURIQueryIsKept checks that the authorization response and the error response keep the query of the registered redirect URI.
//
//conformance:covers OAUTH21D16-2.3-03
func TestRedirectURIQueryIsKept(t *testing.T) {
	uri := redirectURI + "?tenant=a"
	a := newAuthorizationServer(t, publicClient("tenant", uri))
	params := withRedirectURI(uri)
	params.Set("client_id", "tenant")
	u := a.login(a.authorize(params), "alice")
	if q := u.Query(); endpoint(u) != redirectURI || q.Get("tenant") != "a" || q.Get("code") == "" {
		t.Fatalf("got redirect %s, want tenant=a and a code", u)
	}
	u = a.deny(a.pending(a.authorize(params)).ID)
	if q := u.Query(); endpoint(u) != redirectURI || q.Get("tenant") != "a" || q.Get("error") != "access_denied" {
		t.Fatalf("got redirect %s, want tenant=a and access_denied", u)
	}
}

// nativeCode runs an authorization request of the public Client id for redirect through login, checks that the code reaches redirect, and returns the code.
func (a *authorizationServer) nativeCode(id, redirect string) string {
	a.t.Helper()
	params := authorizeParams()
	params.Set("client_id", id)
	params.Set("redirect_uri", redirect)
	u := a.login(a.authorize(params), "alice")
	code := u.Query().Get("code")
	if !strings.HasPrefix(u.String(), redirect+"?") || code == "" {
		a.t.Fatalf("got redirect %s, want a code at %s", u, redirect)
	}
	return code
}

// nativeTokenParams returns a token request of the public Client id for the code it gets at redirect.
func (a *authorizationServer) nativeTokenParams(id, redirect string) url.Values {
	a.t.Helper()
	params := tokenParams(a.nativeCode(id, redirect))
	params.Set("client_id", id)
	return params
}

// TestNativeAppPKCE checks that a public native app Client with a loopback redirect URI redeems its code only with the code verifier of its code challenge.
//
//conformance:covers RFC8252-6-02
func TestNativeAppPKCE(t *testing.T) {
	a := newAuthorizationServer(t, publicClient(nativeID, nativeRedirectURI))
	for _, v := range []string{"", s256(verifier)[:43]} {
		status, _, body := a.token(withVerifier(a.nativeTokenParams(nativeID, "http://127.0.0.1:51004/cb"), v), nil)
		if status == http.StatusOK {
			t.Fatalf("got body %v for code_verifier %q, want an error", body, v)
		}
	}
	a.tokens(a.nativeTokenParams(nativeID, "http://127.0.0.1:51004/cb"), nil)
}

// TestNativeAppRedirectOptions checks that native app Clients can use a private-use URI scheme, a claimed https URI and a loopback IP redirect URI.
//
//conformance:covers RFC8252-7-01
func TestNativeAppRedirectOptions(t *testing.T) {
	for registered, requested := range map[string]string{
		"com.example.app:/oauth2redirect/example-provider": "com.example.app:/oauth2redirect/example-provider",
		"https://app.example.com/oauth2redirect":           "https://app.example.com/oauth2redirect",
		"http://127.0.0.1/oauth2redirect":                  "http://127.0.0.1:51004/oauth2redirect",
	} {
		t.Run(registered, func(t *testing.T) {
			a := newAuthorizationServer(t, publicClient(nativeID, registered))
			a.tokens(a.nativeTokenParams(nativeID, requested), nil)
		})
	}
}

// TestLoopbackRedirectAllowsAnyPort checks that a loopback IP redirect URI registered without a port matches with any port, the lowest and the highest included.
//
//conformance:covers RFC8252-7.3-01
func TestLoopbackRedirectAllowsAnyPort(t *testing.T) {
	a := newAuthorizationServer(t, publicClient(nativeID, nativeRedirectURI, "http://[::1]/cb"))
	for _, host := range []string{"127.0.0.1", "[::1]"} {
		for _, port := range []string{"1", "80", "8080", "49152", "65535"} {
			a.nativeCode(nativeID, "http://"+host+":"+port+"/cb")
		}
	}
}

// TestClientTypeDecidesAuthentication checks that the recorded Client type decides how a token request is processed: a public Client redeems its code with only its client_id, a confidential one with the same registration must authenticate.
//
//conformance:covers RFC8252-8.4-02
func TestClientTypeDecidesAuthentication(t *testing.T) {
	confidential := confidentialClient(t)
	public := confidential
	public.ID, public.Type, public.SecretHash = "public-twin", store.Public, ""
	a := newAuthorizationServer(t, confidential, public)
	redeem := func(id string) (int, map[string]any) {
		params := authorizeParams()
		params.Set("client_id", id)
		token := tokenParams(a.code(params))
		token.Set("client_id", id)
		status, _, body := a.token(token, nil)
		return status, body
	}
	if status, body := redeem(public.ID); status != http.StatusOK {
		t.Fatalf("got status %d and body %v for the public Client, want 200", status, body)
	}
	status, body := redeem(confidential.ID)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
}

// TestRedirectURIMatchesRegistrationExactly checks that a redirect URI that differs from the registered one in any component is rejected without a redirect, except for the port of a loopback redirect URI.
//
//conformance:covers RFC8252-8.4-07
func TestRedirectURIMatchesRegistrationExactly(t *testing.T) {
	a := newAuthorizationServer(t, publicClient(nativeID, nativeRedirectURI, "com.example.app:/cb"))
	for id, uris := range map[string][]string{
		clientID: {redirectURI + "/x", "https://client.example/c", redirectURI + "?a=b", "https://client.example:8443/cb", "http://client.example/cb", "https://other.example/cb"},
		nativeID: {"http://127.0.0.1:51004/cb/x", "http://127.0.0.1:51004/", "http://127.0.0.2:51004/cb", "com.example.app:/cb/x", "com.example.other:/cb"},
	} {
		for _, uri := range uris {
			params := withRedirectURI(uri)
			params.Set("client_id", id)
			a.wantNoRedirect(params)
		}
	}
	a.nativeCode(nativeID, "http://127.0.0.1:51004/cb")
}

// TestRedirectURIUsesExactStringMatching checks that a redirect URI differing from the registered one in any character is not redirected to.
//
//conformance:covers RFC9700-2.1-01
func TestRedirectURIUsesExactStringMatching(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, uri := range []string{redirectURI + "/", redirectURI + "?next=1", redirectURI + "#", "https://client.example/CB", "https://client.example/c", "https://client.example.attacker/cb", "https://attacker.example/cb"} {
		if _, loc := a.sendAuthorization(withRedirectURI(uri)); loc != "" {
			t.Fatalf("%s: got Location %q, want no redirect", uri, loc)
		}
	}
}

// TestRedirectURIIsComparedBySimpleStringComparison checks that redirect URIs equal to the registered one only after normalization are not redirected to.
//
//conformance:covers RFC9700-4.1.3-01
func TestRedirectURIIsComparedBySimpleStringComparison(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, uri := range []string{"https://Client.example/cb", "Https://client.example/cb", "https://client.example:443/cb", "https://client.example/%63%62", "https://client.example/./cb", "https://client.example//cb"} {
		if _, loc := a.sendAuthorization(withRedirectURI(uri)); loc != "" {
			t.Fatalf("%s: got Location %q, want no redirect", uri, loc)
		}
	}
}

// TestLoopbackRedirectURIAcceptsAnyPort checks that a native app's loopback redirect URI gets a code at any port, also when the registration names another port.
//
//conformance:covers RFC9700-4.1.3-02
func TestLoopbackRedirectURIAcceptsAnyPort(t *testing.T) {
	a := newAuthorizationServer(t, publicClient(nativeID, "http://127.0.0.1:8080/cb"))
	for _, uri := range []string{"http://127.0.0.1:65535/cb", "http://127.0.0.1:8080/cb", "http://127.0.0.1:1/cb", "http://127.0.0.1/cb"} {
		a.nativeCode(nativeID, uri)
	}
}

// TestPublicClientIsBoundToRegisteredRedirectURIs checks that a public Client gets the login URL only for a registered redirect URI, and no redirect without one registered.
//
//conformance:covers OAUTH21D16-2.4-05
func TestPublicClientIsBoundToRegisteredRedirectURIs(t *testing.T) {
	a := newAuthorizationServer(t, publicClient("unregistered"))
	a.pending(a.authorize(authorizeParams()))
	if _, loc := a.sendAuthorization(withRedirectURI("https://attacker.example/cb")); loc != "" {
		t.Fatalf("got Location %q for an unregistered redirect URI, want no redirect", loc)
	}
	params := authorizeParams()
	params.Set("client_id", "unregistered")
	if _, loc := a.sendAuthorization(params); loc != "" {
		t.Fatalf("got Location %q for a Client without redirect URIs, want no redirect", loc)
	}
}
