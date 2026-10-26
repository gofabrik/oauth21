package conformance

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/gofabrik/oauth21"
)

// errorChars reports whether s has only the characters %x20-21 / %x23-5B / %x5D-7E that error, error_description and scope values may have.
func errorChars(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r > 0x7e || r == '"' || r == '\\' })
}

// unsupportedResponseType returns the authorization error response for a request with response_type token.
func (a *authorizationServer) unsupportedResponseType() url.Values {
	a.t.Helper()
	return a.authorize(unsupportedParams()).Query()
}

// unsupportedParams returns an authorization request of the public Client with the unsupported response type token.
func unsupportedParams() url.Values {
	params := authorizeParams()
	params.Set("response_type", "token")
	return params
}

// TestAuthorizationEndpointSupportsGet checks that an authorization request sent with GET reaches the login URL.
//
//conformance:covers OAUTH21D16-3.1-05
func TestAuthorizationEndpointSupportsGet(t *testing.T) {
	a := newAuthorizationServer(t)
	status, header, _ := a.send(http.MethodGet, "/authorize?"+authorizeParams().Encode(), "", nil)
	if status != http.StatusFound || !strings.HasPrefix(header.Get("Location"), a.url+"/login?") {
		t.Fatalf("got status %d and Location %q, want a redirect to the login URL", status, header.Get("Location"))
	}
}

// TestEmptyAuthorizationParameterIsOmitted checks that a scope or redirect_uri parameter without a value is treated as omitted, also next to a scope with a value.
//
//conformance:covers OAUTH21D16-3.1-09
func TestEmptyAuthorizationParameterIsOmitted(t *testing.T) {
	a := newAuthorizationServer(t)
	empty := authorizeParams()
	empty.Set("scope", "")
	empty.Set("redirect_uri", "")
	if req := a.pending(a.authorize(empty)); !slices.Equal(req.Scopes, readScope) {
		t.Fatalf("got requested scopes %q, want the default scopes %q", req.Scopes, readScope)
	}
	beside := authorizeParams()
	beside["scope"] = []string{"read", ""}
	if req := a.pending(a.authorize(beside)); !slices.Equal(req.Scopes, readScope) {
		t.Fatalf("got requested scopes %q, want %q", req.Scopes, readScope)
	}
}

// TestAuthorizationRequiresResponseType checks that a request without response_type gets invalid_request.
//
//conformance:covers OAUTH21D16-4.1.1-01
func TestAuthorizationRequiresResponseType(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Del("response_type")
	a.wantAuthorizationError(a.authorize(params), "invalid_request", "response_type")
}

// TestAuthorizationResponseCarriesCode checks that a completed request is answered with a code.
//
//conformance:covers OAUTH21D16-4.1.2-01
func TestAuthorizationResponseCarriesCode(t *testing.T) {
	a := newAuthorizationServer(t)
	if u := a.login(a.authorize(authorizeParams()), "alice"); u.Query().Get("code") == "" {
		t.Fatalf("got redirect %s, want a code", u)
	}
}

// TestAuthorizationResponseCarriesState checks that the authorization response returns the state of the request.
//
//conformance:covers OAUTH21D16-4.1.2-04
func TestAuthorizationResponseCarriesState(t *testing.T) {
	a := newAuthorizationServer(t)
	if u := a.login(a.authorize(authorizeParams()), "alice"); u.Query().Get("state") != state {
		t.Fatalf("got redirect %s, want state %q", u, state)
	}
}

// tenantAuthorization sends an authorization request to an Authorization Server whose issuer has the path /tenant and returns the server, its issuer and the redirect location.
func tenantAuthorization(t *testing.T, params url.Values) (*authorizationServer, string, *url.URL) {
	t.Helper()
	a := newConfiguredServer(t, func(c *oauth21.Config) { c.Issuer += "/tenant" })
	status, header, _ := a.send(http.MethodGet, "/tenant/authorize?"+params.Encode(), "", nil)
	if status != http.StatusFound {
		t.Fatalf("got status %d, want a redirect", status)
	}
	return a, a.url + "/tenant", a.redirect(header.Get("Location"))
}

// TestAuthorizationResponseCarriesIssuer checks that the authorization response names the issuer, including its path, in iss.
//
//conformance:covers OAUTH21D16-4.1.2-05
func TestAuthorizationResponseCarriesIssuer(t *testing.T) {
	a, issuer, loc := tenantAuthorization(t, authorizeParams())
	if u := a.login(loc, "alice"); u.Query().Get("iss") != issuer {
		t.Fatalf("got redirect %s, want iss %q", u, issuer)
	}
}

// TestAuthorizationResponseCarriesNoToken checks that the authorization response carries no access token or refresh token in its URL.
//
//conformance:covers OAUTH21D16-7.1.3.7-01
func TestAuthorizationResponseCarriesNoToken(t *testing.T) {
	a := newAuthorizationServer(t)
	u := a.login(a.authorize(authorizeParams()), "alice")
	if q := u.Query(); q.Has("access_token") || q.Has("refresh_token") || u.Fragment != "" {
		t.Fatalf("got redirect %s, want no token in it", u)
	}
}

// TestAuthorizationErrorCarriesError checks that every redirected error response carries its error.
//
//conformance:covers OAUTH21D16-4.1.2.1-09
func TestAuthorizationErrorCarriesError(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, q := range a.authorizationErrors() {
		if q.Get("error") == "" {
			t.Fatalf("got %v, want an error", q)
		}
	}
}

// authorizationErrors returns the redirected error responses for an unsupported response type, a missing code challenge, an unsupported code challenge method and an unknown scope, the last two with characters outside those error values may have, and for a denied request.
func (a *authorizationServer) authorizationErrors() []url.Values {
	a.t.Helper()
	challenge := authorizeParams()
	challenge.Del("code_challenge")
	method := authorizeParams()
	method.Set("code_challenge_method", "plain\u00e9\"\\")
	scope := authorizeParams()
	scope.Set("scope", "read \u00fcnknown")
	denied := a.deny(a.pending(a.authorize(authorizeParams())).ID)
	return []url.Values{a.unsupportedResponseType(), a.authorize(challenge).Query(), a.authorize(method).Query(), a.authorize(scope).Query(), denied.Query()}
}

// TestAuthorizationErrorCodeCharacters checks that redirected error codes use only the allowed characters.
//
//conformance:covers OAUTH21D16-4.1.2.1-10
func TestAuthorizationErrorCodeCharacters(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, q := range a.authorizationErrors() {
		if code := q.Get("error"); code == "" || !errorChars(code) {
			t.Fatalf("got error %q, want a code of the allowed characters", code)
		}
	}
}

// TestAuthorizationErrorCarriesState checks that every redirected error response returns the state of the request.
//
//conformance:covers OAUTH21D16-4.1.2.1-16
func TestAuthorizationErrorCarriesState(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, q := range a.authorizationErrors() {
		if q.Get("state") != state {
			t.Fatalf("got %v, want state %q", q, state)
		}
	}
}

// TestAuthorizationErrorCarriesIssuer checks that a redirected error response names the issuer, including its path, in iss.
//
//conformance:covers OAUTH21D16-4.1.2.1-17
func TestAuthorizationErrorCarriesIssuer(t *testing.T) {
	params := authorizeParams()
	params.Set("response_type", "token")
	_, issuer, loc := tenantAuthorization(t, params)
	if q := loc.Query(); q.Get("error") == "" || q.Get("iss") != issuer {
		t.Fatalf("got %v, want an error with iss %q", q, issuer)
	}
}

// TestUnknownAuthorizationParameterIsIgnored checks that a request with an unrecognized parameter, sent once or repeated, reaches the login URL.
//
//conformance:covers OAUTH21D16-3.1-07
func TestUnknownAuthorizationParameterIsIgnored(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, values := range [][]string{{"value"}, {"value", "other"}} {
		params := authorizeParams()
		params["unknown"] = values
		a.pending(a.authorize(params))
	}
}

// TestRepeatedAuthorizationParameterIsRejected checks that a request with a repeated parameter, with different or equal values, is neither redirected nor passed to the login URL.
//
//conformance:covers OAUTH21D16-3.1-08
func TestRepeatedAuthorizationParameterIsRejected(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, values := range [][]string{{"read", "write"}, {"read", "read"}} {
		params := authorizeParams()
		params["scope"] = values
		if status, loc := a.sendAuthorization(params); status != http.StatusBadRequest || loc != "" {
			t.Fatalf("scope %q: got status %d and Location %q, want 400 without redirect", values, status, loc)
		}
	}
}

// TestAuthorizationEndpointHasNoCORS checks that the authorization endpoint answers neither a cross-origin GET or POST request nor a preflight with CORS headers.
//
//conformance:covers OAUTH21D16-3.1-11
func TestAuthorizationEndpointHasNoCORS(t *testing.T) {
	a := newAuthorizationServer(t)
	origin := http.Header{"Origin": {"https://other.example"}, "Access-Control-Request-Method": {"GET"}}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
		path, form := "/authorize?"+authorizeParams().Encode(), ""
		if method == http.MethodPost {
			path, form = "/authorize", authorizeParams().Encode()
		}
		status, header, _ := a.send(method, path, form, origin)
		if header.Get("Access-Control-Allow-Origin") != "" || method == http.MethodOptions && status < 300 {
			t.Fatalf("%s: got status %d and Access-Control-Allow-Origin %q, want no CORS", method, status, header.Get("Access-Control-Allow-Origin"))
		}
	}
}

// TestAuthorizationRequiresClientID checks that a request without client_id is not redirected.
//
//conformance:covers OAUTH21D16-4.1.1-04
func TestAuthorizationRequiresClientID(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Del("client_id")
	if status, loc := a.sendAuthorization(params); status != http.StatusBadRequest || loc != "" {
		t.Fatalf("got status %d and Location %q, want 400 without redirect", status, loc)
	}
}

// TestRedirectURIRequiredWithSeveralRegistered checks that a request without redirect_uri from a Client with several redirect URIs is not redirected.
//
//conformance:covers OAUTH21D16-4.1.1-08
func TestRedirectURIRequiredWithSeveralRegistered(t *testing.T) {
	a := newAuthorizationServer(t, publicClient("two", redirectURI, "https://client.example/other"))
	params := authorizeParams()
	params.Set("client_id", "two")
	params.Del("redirect_uri")
	if status, loc := a.sendAuthorization(params); status != http.StatusBadRequest || loc != "" {
		t.Fatalf("got status %d and Location %q, want 400 without redirect", status, loc)
	}
}

// TestAuthorizationErrorDescriptionCharacters checks that redirected error descriptions use only the allowed characters.
//
//conformance:covers OAUTH21D16-4.1.2.1-12
func TestAuthorizationErrorDescriptionCharacters(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, q := range a.authorizationErrors() {
		if d := q.Get("error_description"); d == "" || !errorChars(d) {
			t.Fatalf("got error_description %q, want only the allowed characters", d)
		}
	}
}

// TestLongStateIsKept checks that a long state value is returned whole.
//
//conformance:covers OAUTH21D16-1.7.1-01
func TestLongStateIsKept(t *testing.T) {
	a := newAuthorizationServer(t)
	long := strings.Repeat("s", 4000)
	params := authorizeParams()
	params.Set("state", long)
	if u := a.login(a.authorize(params), "alice"); u.Query().Get("state") != long {
		t.Fatalf("got state of %d characters, want %d", len(u.Query().Get("state")), len(long))
	}
}

// TestHostileParametersAreContained checks that a state with characters that delimit URL parts is returned unchanged without adding parameters, in an authorization response and in an error response, and that redirect_uri values crafted to reach another host are not redirected to.
//
//conformance:covers OAUTH21D16-7.12-01
func TestHostileParametersAreContained(t *testing.T) {
	a := newAuthorizationServer(t)
	hostile := `x&code=evil&iss=https://evil.example#frag <script>"'`
	params := authorizeParams()
	params.Set("state", hostile)
	failing := unsupportedParams()
	failing.Set("state", hostile)
	for _, u := range []*url.URL{a.login(a.authorize(params), "alice"), a.authorize(failing)} {
		if q := u.Query(); q.Get("state") != hostile || q.Get("code") == "evil" || q.Get("iss") != a.url || u.Fragment != "" {
			t.Fatalf("got redirect %s, want state %q returned unchanged", u, hostile)
		}
	}
	for _, uri := range []string{
		redirectURI + "#@evil.example",
		"https://client.example@evil.example/cb",
		redirectURI + "?redirect_uri=https://evil.example",
		redirectURI + "\r\nLocation: https://evil.example",
		"javascript:alert(1)//client.example/cb",
	} {
		if _, loc := a.sendAuthorization(withRedirectURI(uri)); loc != "" {
			t.Fatalf("redirect_uri %q: got Location %q, want no redirect", uri, loc)
		}
	}
}

// TestResponseParametersAreUTF8 checks that the authorization response encodes a non-ASCII state as UTF-8 before escaping it.
//
//conformance:covers OAUTH21D16-B-01
func TestResponseParametersAreUTF8(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("state", "zoë")
	if u := a.login(a.authorize(params), "alice"); !strings.Contains(u.RawQuery, "state=zo%C3%AB") {
		t.Fatalf("got query %q, want state=zo%%C3%%AB", u.RawQuery)
	}
}

// TestAuthorizationResponseParametersAppearOnce checks that the redirects of the authorization endpoint and of a completed or denied request carry each parameter once.
//
//conformance:covers OAUTH21D16-3.1-12
func TestAuthorizationResponseParametersAppearOnce(t *testing.T) {
	a := newAuthorizationServer(t)
	_, login := a.sendAuthorization(authorizeParams())
	params := authorizeParams()
	params.Set("response_type", "token")
	_, failed := a.sendAuthorization(params)
	completed, err := a.srv.Complete(t.Context(), a.pending(a.authorize(authorizeParams())).ID, oauth21.Completion{Subject: "alice", Scopes: readScope})
	if err != nil {
		t.Fatal(err)
	}
	denied, err := a.srv.Deny(t.Context(), a.pending(a.authorize(authorizeParams())).ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, loc := range []string{login, failed, completed, denied} {
		a.redirect(loc)
	}
}

// postedAuthorization sends an authorization request as a POST form body carrying a password and returns the status and Location of the response.
func (a *authorizationServer) postedAuthorization(params url.Values) (int, string) {
	a.t.Helper()
	params.Set("password", "hunter2")
	status, header, _ := a.send(http.MethodPost, "/authorize", params.Encode(), nil)
	return status, header.Get("Location")
}

// TestPostedCredentialsAreNotForwarded checks that redirecting a POST authorization request that carries a password, to the login URL or to the Client, neither repeats the request body nor puts the password in the redirect.
//
//conformance:covers OAUTH21D16-3.1-10
func TestPostedCredentialsAreNotForwarded(t *testing.T) {
	a := newAuthorizationServer(t)
	for target, params := range map[string]url.Values{a.url + "/login?": authorizeParams(), redirectURI + "?": unsupportedParams()} {
		status, loc := a.postedAuthorization(params)
		if status != http.StatusFound && status != http.StatusSeeOther || !strings.HasPrefix(loc, target) || strings.Contains(loc, "hunter2") {
			t.Fatalf("got status %d and Location %q, want a 302 or 303 to %s without the password", status, loc, target)
		}
	}
}

// TestAuthorizationRedirectsAreNot307 checks that the authorization endpoint never redirects with 307, for GET and POST requests, to the login URL and to the Client.
//
//conformance:covers OAUTH21D16-7.5.4-01
func TestAuthorizationRedirectsAreNot307(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, params := range []url.Values{authorizeParams(), unsupportedParams()} {
		get, _ := a.sendAuthorization(params)
		post, _ := a.postedAuthorization(params)
		if get == http.StatusTemporaryRedirect || post == http.StatusTemporaryRedirect || get/100 != 3 || post/100 != 3 {
			t.Fatalf("got statuses %d and %d, want redirects other than 307", get, post)
		}
	}
}

// TestAuthorizationErrorURIIsURIReference checks that a redirected error response carries error_uri only as a URI-reference.
//
//conformance:covers OAUTH21D16-4.1.2.1-14
func TestAuthorizationErrorURIIsURIReference(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, q := range a.authorizationErrors() {
		if q.Has("error_uri") && !uriReference(q.Get("error_uri")) {
			t.Fatalf("got error_uri %q, want a URI-reference", q.Get("error_uri"))
		}
	}
}

// TestAuthorizationErrorURICharacters checks that a redirected error response carries error_uri only with the allowed characters.
//
//conformance:covers OAUTH21D16-4.1.2.1-15
func TestAuthorizationErrorURICharacters(t *testing.T) {
	a := newAuthorizationServer(t)
	for _, q := range a.authorizationErrors() {
		if q.Has("error_uri") && !uriChars(q.Get("error_uri")) {
			t.Fatalf("got error_uri %q, want only the allowed characters", q.Get("error_uri"))
		}
	}
}
