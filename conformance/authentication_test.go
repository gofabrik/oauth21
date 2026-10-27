package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gofabrik/oauth21"
)

// failingParams returns authorization requests of the public Client that fail after its redirect URI is validated, by what makes each fail.
func failingParams() map[string]url.Values {
	missing, unsupported, challenge, method, scope := authorizeParams(), authorizeParams(), authorizeParams(), authorizeParams(), authorizeParams()
	missing.Del("response_type")
	unsupported.Set("response_type", "token")
	challenge.Del("code_challenge")
	method.Set("code_challenge_method", "plain")
	scope.Set("scope", "unknown")
	return map[string]url.Values{
		"missing response_type":     missing,
		"unsupported response_type": unsupported,
		"missing code challenge":    challenge,
		"plain method":              method,
		"unknown scope":             scope,
	}
}

// TestErrorsAreNotRedirectedBeforeLogin checks that no error found after the redirect URI is validated is redirected anywhere but the login URL.
//
//conformance:covers OAUTH21D16-7.13.2-02
func TestErrorsAreNotRedirectedBeforeLogin(t *testing.T) {
	a := newAuthorizationServer(t)
	for name, params := range failingParams() {
		if _, loc := a.sendAuthorization(params); !strings.HasPrefix(loc, a.url+"/login?") {
			t.Fatalf("%s: got Location %q, want the login URL", name, loc)
		}
	}
}

// TestFailedRequestRevealsNothingBeforeLogin checks that a request with an unsupported response type is redirected to the login URL with only its request_id, not its error, state or issuer.
//
//conformance:covers RFC9700-4.11.2-02
func TestFailedRequestRevealsNothingBeforeLogin(t *testing.T) {
	a := newAuthorizationServer(t)
	_, loc := a.sendAuthorization(unsupportedParams())
	u := a.redirect(loc)
	if q := u.Query(); endpoint(u) != a.url+"/login" || len(q) != 1 || q.Get("request_id") == "" {
		t.Fatalf("got Location %q, want the login URL with only request_id", loc)
	}
}

// TestAuthorizationEndpointRedirectsOnlyToLogin checks that valid and failing GET requests, for the registered redirect URI or another one, are never redirected anywhere but the login URL.
//
//conformance:covers OAUTH21D16-7.13.2-03
func TestAuthorizationEndpointRedirectsOnlyToLogin(t *testing.T) {
	a := newAuthorizationServer(t)
	a.wantRedirectsOnlyToLogin(func(params url.Values) string {
		_, loc := a.sendAuthorization(params)
		return loc
	})
}

// TestPostedRequestsRedirectOnlyToLogin checks that valid and failing POST requests, for the registered redirect URI or another one, are never redirected anywhere but the login URL.
//
//conformance:covers RFC9700-4.11.2-03
func TestPostedRequestsRedirectOnlyToLogin(t *testing.T) {
	a := newAuthorizationServer(t)
	a.wantRedirectsOnlyToLogin(func(params url.Values) string {
		_, header, _ := a.send(http.MethodPost, "/authorize", params.Encode(), nil)
		return header.Get("Location")
	})
}

// wantRedirectsOnlyToLogin checks that send redirects valid and failing requests, for the registered redirect URI or another one, nowhere but to the login URL.
func (a *authorizationServer) wantRedirectsOnlyToLogin(send func(url.Values) string) {
	a.t.Helper()
	requests := failingParams()
	requests["valid"] = authorizeParams()
	for name, params := range requests {
		for _, uri := range []string{redirectURI, "https://attacker.example/cb"} {
			params.Set("redirect_uri", uri)
			if loc := send(params); loc != "" && !strings.HasPrefix(loc, a.url+"/login?") {
				a.t.Fatalf("%s to %s: got Location %q, want none or the login URL", name, uri, loc)
			}
		}
	}
}

// TestUntrustedRedirectURIIsExplained checks that the Host Application can show the user why a failing request with an unregistered redirect URI is not redirected.
//
//conformance:covers OAUTH21D16-7.13.2-05
func TestUntrustedRedirectURIIsExplained(t *testing.T) {
	var got oauth21.AuthorizationError
	a := newConfiguredServer(t, func(c *oauth21.Config) {
		c.RenderError = func(w http.ResponseWriter, _ *http.Request, e oauth21.AuthorizationError) {
			got = e
			w.WriteHeader(e.Status)
		}
	})
	params := unsupportedParams()
	params.Set("redirect_uri", "https://attacker.example/cb")
	a.wantNoRedirect(params)
	if got.Code != "invalid_request" || !strings.Contains(got.Description, "redirect_uri") {
		t.Fatalf("got rendered error %+v, want invalid_request naming redirect_uri", got)
	}
}

// TestUntrustedRedirectURIIsNotRedirected checks that failing requests with a redirect URI the Client did not register get neither a redirect nor the login URL.
//
//conformance:covers OAUTH21D16-7.13.2-04
func TestUntrustedRedirectURIIsNotRedirected(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, params := range failingParams() {
		params.Set("redirect_uri", "https://attacker.example/cb")
		a.wantNoRedirect(params)
	}
}

// TestRedirectURIOfAnotherClientIsNotRedirected checks that a failing request with a redirect URI only another Client registered gets no redirect.
//
//conformance:covers RFC9700-4.11.2-04
func TestRedirectURIOfAnotherClientIsNotRedirected(t *testing.T) {
	other := "https://other.example/cb"
	a := newAuthorizationServer(t, publicClient("other", other))
	params := unsupportedParams()
	params.Set("redirect_uri", other)
	a.wantNoRedirect(params)
}

// TestAuthorizationEndpointIsNoOpenRedirector checks that a redirect_uri the Client did not register is never redirected to, for a valid request, a failing one and one of an unknown Client.
//
//conformance:covers RFC9700-2.1-10
func TestAuthorizationEndpointIsNoOpenRedirector(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, params := range []url.Values{authorizeParams(), unsupportedParams(), unknownClientParams()} {
		params.Set("redirect_uri", "https://attacker.example/cb")
		a.wantNoRedirect(params)
	}
}
