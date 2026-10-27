package conformance

import (
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gofabrik/oauth21"
)

// metadata fetches the metadata document from the well-known URI of issuer (RFC 8414 3) and returns it decoded.
func (a *authorizationServer) metadata(issuer string) map[string]any {
	a.t.Helper()
	u, err := url.Parse(issuer)
	if err != nil {
		a.t.Fatal(err)
	}
	status, _, body := a.sendJSON(http.MethodGet, "/.well-known/oauth-authorization-server"+strings.TrimSuffix(u.Path, "/"), "", nil)
	if status != http.StatusOK {
		a.t.Fatalf("got status %d and body %v, want 200", status, body)
	}
	return body
}

// endpointPath returns the path of endpoint, an absolute URL on the Authorization Server.
func (a *authorizationServer) endpointPath(endpoint any) string {
	a.t.Helper()
	s, ok := endpoint.(string)
	if !ok || !strings.HasPrefix(s, a.url+"/") {
		a.t.Fatalf("got endpoint %v, want a URL on %s", endpoint, a.url)
	}
	return strings.TrimPrefix(s, a.url)
}

// TestMetadata checks that the metadata document names the issuer, the endpoints and the supported capabilities.
func TestMetadata(t *testing.T) {
	a := newAuthorizationServer(t)
	want := map[string]any{
		"issuer":                                         a.url,
		"authorization_endpoint":                         a.url + "/authorize",
		"token_endpoint":                                 a.url + "/token",
		"revocation_endpoint":                            a.url + "/revoke",
		"introspection_endpoint":                         a.url + "/introspect",
		"scopes_supported":                               []any{"read", "write", "admin"},
		"response_types_supported":                       []any{"code"},
		"response_modes_supported":                       []any{"query"},
		"grant_types_supported":                          []any{"authorization_code", "refresh_token", "client_credentials"},
		"token_endpoint_auth_methods_supported":          []any{"none", "client_secret_basic", "client_secret_post"},
		"revocation_endpoint_auth_methods_supported":     []any{"none", "client_secret_basic", "client_secret_post"},
		"introspection_endpoint_auth_methods_supported":  []any{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":               []any{"S256"},
		"authorization_response_iss_parameter_supported": true,
	}
	if got := a.metadata(a.url); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestMetadataFollowsConfiguredPaths checks that a Client using only the metadata of an issuer with a path and a trailing slash reaches every endpoint.
func TestMetadataFollowsConfiguredPaths(t *testing.T) {
	a := newConfiguredServer(t, func(c *oauth21.Config) {
		c.Issuer += "/tenant/"
		c.Paths = oauth21.Paths{Authorization: "/oauth/authorize", Token: "/oauth/token", Revocation: "/oauth/revoke", Introspection: "/oauth/introspect"} // #nosec G101 -- endpoint paths, not credentials
	}, newIntrospectionClients(t)...)
	m := a.metadata(a.url + "/tenant/")
	if m["issuer"] != a.url+"/tenant/" {
		t.Fatalf("got issuer %v, want %s", m["issuer"], a.url+"/tenant/")
	}
	status, header, _ := a.send(http.MethodGet, a.endpointPath(m["authorization_endpoint"])+"?"+authorizeParams().Encode(), "", nil)
	if status != http.StatusFound {
		t.Fatalf("got status %d from the authorization endpoint, want a redirect", status)
	}
	loc, err := url.Parse(header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := a.login(loc, "alice").Query().Get("code")
	status, _, body := a.sendJSON(http.MethodPost, a.endpointPath(m["token_endpoint"]), tokenParams(code).Encode(), nil)
	access, ok := body["access_token"].(string)
	if status != http.StatusOK || !ok {
		t.Fatalf("got status %d and body %v from the token endpoint, want an access token", status, body)
	}
	status, _, body = a.sendJSON(http.MethodPost, a.endpointPath(m["introspection_endpoint"]), url.Values{"token": {access}}.Encode(), basic(resourceServerID, secret))
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("got status %d and body %v from the introspection endpoint, want an active token", status, body)
	}
	status, _, _ = a.send(http.MethodPost, a.endpointPath(m["revocation_endpoint"]), url.Values{"token": {access}, "client_id": {clientID}}.Encode(), nil)
	if status != http.StatusOK {
		t.Fatalf("got status %d from the revocation endpoint, want 200", status)
	}
	status, _, body = a.sendJSON(http.MethodPost, a.endpointPath(m["introspection_endpoint"]), url.Values{"token": {access}}.Encode(), basic(resourceServerID, secret))
	if status != http.StatusOK || len(body) != 1 || body["active"] != false {
		t.Fatalf("got status %d and body %v after revocation, want only active false", status, body)
	}
}

// TestMetadataNamesCodeChallengeMethods checks that the metadata document names S256 as the only code challenge method.
//
//conformance:covers OAUTH21D16-7.10-04
func TestMetadataNamesCodeChallengeMethods(t *testing.T) {
	a := newAuthorizationServer(t)
	if got := a.metadata(a.url)["code_challenge_methods_supported"]; !reflect.DeepEqual(got, []any{"S256"}) {
		t.Fatalf("got code_challenge_methods_supported %v, want [S256]", got)
	}
}

// endpointURLs returns the issuer and the endpoint URLs in the metadata of an Authorization Server with an issuer path and configured endpoint paths.
func endpointURLs(t *testing.T) []string {
	t.Helper()
	a := newConfiguredServer(t, func(c *oauth21.Config) {
		c.Issuer += "/tenant"
		c.Paths = oauth21.Paths{Authorization: "/oauth/authorize", Token: "/oauth/token", Revocation: "/oauth/revoke", Introspection: "/oauth/introspect"} // #nosec G101 -- endpoint paths, not credentials
	})
	m := a.metadata(a.url + "/tenant")
	urls := []string{a.url + "/.well-known/oauth-authorization-server/tenant"}
	for name, v := range m {
		if s, ok := v.(string); ok && (name == "issuer" || strings.HasSuffix(name, "_endpoint")) {
			urls = append(urls, s)
		}
	}
	return urls
}

// TestEndpointURLsAreHTTPS checks that the issuer, the metadata URL and every endpoint URL of the metadata use the https scheme.
//
//conformance:covers OAUTH21D16-1.5-02
func TestEndpointURLsAreHTTPS(t *testing.T) {
	for _, u := range endpointURLs(t) {
		if !strings.HasPrefix(u, "https://") {
			t.Fatalf("got URL %q, want https", u)
		}
	}
}

// metadataURL returns the URL the metadata of an Authorization Server with configured endpoint paths names under name, as written in the metadata.
func metadataURL(t *testing.T, name string) string {
	t.Helper()
	a := newConfiguredServer(t, func(c *oauth21.Config) {
		c.Paths = oauth21.Paths{Authorization: "/oauth/authorize", Token: "/oauth/token"} // #nosec G101 -- endpoint paths, not credentials
	})
	s, _ := a.metadata(a.url)[name].(string)
	if _, err := url.Parse(s); err != nil || s == "" {
		t.Fatalf("got %s %q, want a URL", name, s)
	}
	return s
}

// TestAuthorizationEndpointHasNoFragment checks that the authorization endpoint URL in the metadata has no fragment, not even an empty one.
//
//conformance:covers OAUTH21D16-3.1-02
func TestAuthorizationEndpointHasNoFragment(t *testing.T) {
	if u := metadataURL(t, "authorization_endpoint"); strings.Contains(u, "#") {
		t.Fatalf("got authorization_endpoint %s, want no fragment", u)
	}
}

// TestTokenEndpointHasNoFragment checks that the token endpoint URL in the metadata has no fragment, not even an empty one.
//
//conformance:covers OAUTH21D16-3.2-01
func TestTokenEndpointHasNoFragment(t *testing.T) {
	if u := metadataURL(t, "token_endpoint"); strings.Contains(u, "#") {
		t.Fatalf("got token_endpoint %s, want no fragment", u)
	}
}

// TestMetadataProvidesIssuer checks that the metadata document provides the issuer identifier, also one with a path.
//
//conformance:covers RFC9207-2.3-01
func TestMetadataProvidesIssuer(t *testing.T) {
	a := newConfiguredServer(t, func(c *oauth21.Config) { c.Issuer += "/tenant" })
	if got := a.metadata(a.url + "/tenant")["issuer"]; got != a.url+"/tenant" {
		t.Fatalf("got issuer %v, want %s", got, a.url+"/tenant")
	}
}

// TestMetadataIssuerIsIss checks that the issuer of the metadata document is identical to iss in authorization responses and error responses, also for an issuer with a path and a trailing slash.
//
//conformance:covers RFC9207-2.3-02
func TestMetadataIssuerIsIss(t *testing.T) {
	for _, path := range []string{"", "/tenant", "/tenant/"} {
		t.Run(path, func(t *testing.T) {
			a := newConfiguredServer(t, func(c *oauth21.Config) { c.Issuer += path })
			issuer := a.metadata(a.url + path)["issuer"]
			unsupported := authorizeParams()
			unsupported.Set("response_type", "token")
			success := a.login(a.authorizationRedirect(authorizeParams()), "alice")
			for _, u := range []*url.URL{success, a.denyAt(a.authorizationRedirect(unsupported))} {
				if got := u.Query().Get("iss"); got != issuer {
					t.Fatalf("got iss %q, want the metadata issuer %v", got, issuer)
				}
			}
		})
	}
}

// TestMetadataAnnouncesIss checks that the metadata document sets authorization_response_iss_parameter_supported to true.
//
//conformance:covers RFC9207-2.3-03
func TestMetadataAnnouncesIss(t *testing.T) {
	a := newAuthorizationServer(t)
	if got := a.metadata(a.url)["authorization_response_iss_parameter_supported"]; got != true {
		t.Fatalf("got authorization_response_iss_parameter_supported %v, want true", got)
	}
}

// TestMetadataHasIssuer checks that the metadata document has the issuer.
//
//conformance:covers RFC8414-2-01
func TestMetadataHasIssuer(t *testing.T) {
	a := newAuthorizationServer(t)
	if got := a.metadata(a.url)["issuer"]; got != a.url {
		t.Fatalf("got issuer %v, want %s", got, a.url)
	}
}

// TestMetadataHasAuthorizationEndpoint checks that the metadata document names the authorization endpoint.
//
//conformance:covers RFC8414-2-02
func TestMetadataHasAuthorizationEndpoint(t *testing.T) {
	a := newAuthorizationServer(t)
	if got := a.metadata(a.url)["authorization_endpoint"]; got != a.url+a.srv.Paths().Authorization {
		t.Fatalf("got authorization_endpoint %v, want %s", got, a.url+a.srv.Paths().Authorization)
	}
}

// TestMetadataHasTokenEndpoint checks that the metadata document names the token endpoint.
//
//conformance:covers RFC8414-2-03
func TestMetadataHasTokenEndpoint(t *testing.T) {
	a := newAuthorizationServer(t)
	if got := a.metadata(a.url)["token_endpoint"]; got != a.url+a.srv.Paths().Token {
		t.Fatalf("got token_endpoint %v, want %s", got, a.url+a.srv.Paths().Token)
	}
}

// TestMetadataHasResponseTypes checks that the metadata document names code as the only supported response type.
//
//conformance:covers RFC8414-2-11
func TestMetadataHasResponseTypes(t *testing.T) {
	a := newAuthorizationServer(t)
	if got := a.metadata(a.url)["response_types_supported"]; !reflect.DeepEqual(got, []any{"code"}) {
		t.Fatalf("got response_types_supported %v, want [code]", got)
	}
}

// TestMetadataAtWellKnownPath checks that the metadata document of an issuer with a path is served with the well-known URI string inserted between the host and the path, and not after the path.
//
//conformance:covers RFC8414-3-01
func TestMetadataAtWellKnownPath(t *testing.T) {
	a := newConfiguredServer(t, func(c *oauth21.Config) { c.Issuer += "/tenant" })
	if got := a.metadata(a.url + "/tenant")["issuer"]; got != a.url+"/tenant" {
		t.Fatalf("got issuer %v, want %s", got, a.url+"/tenant")
	}
	if status, _, _ := a.send(http.MethodGet, "/tenant/.well-known/oauth-authorization-server", "", nil); status != http.StatusNotFound {
		t.Fatalf("got status %d after the path, want 404", status)
	}
}

// TestMetadataURLIsHTTPS checks that the metadata URL formed from the published issuer, also one with a path, is an https URL that serves the metadata document.
//
//conformance:covers RFC8414-3-02
func TestMetadataURLIsHTTPS(t *testing.T) {
	a := newConfiguredServer(t, func(c *oauth21.Config) { c.Issuer += "/tenant" })
	issuer, _ := a.metadata(a.url + "/tenant")["issuer"].(string)
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" {
		t.Fatalf("got issuer %q, want an https URL", issuer)
	}
	u.Path = "/.well-known/oauth-authorization-server" + strings.TrimSuffix(u.Path, "/")
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.TLS == nil {
		t.Fatalf("got status %d from %s, want 200 over TLS", resp.StatusCode, u)
	}
}

// TestMetadataPathDropsTrailingSlash checks that the metadata path of an issuer whose path ends in a slash drops the slash.
//
//conformance:covers RFC8414-3.1-02
func TestMetadataPathDropsTrailingSlash(t *testing.T) {
	a := newConfiguredServer(t, func(c *oauth21.Config) { c.Issuer += "/tenant/" })
	status, _, body := a.sendJSON(http.MethodGet, "/.well-known/oauth-authorization-server/tenant", "", nil)
	if status != http.StatusOK || body["issuer"] != a.url+"/tenant/" {
		t.Fatalf("got status %d and issuer %v, want 200 and %s", status, body["issuer"], a.url+"/tenant/")
	}
	if status, _, _ := a.send(http.MethodGet, "/.well-known/oauth-authorization-server/tenant/", "", nil); status != http.StatusNotFound {
		t.Fatalf("got status %d with the trailing slash, want 404", status)
	}
}

// metadataNames are the metadata names of RFC 8414 2 and authorization_response_iss_parameter_supported of RFC 9207 3.
var metadataNames = []string{
	"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "registration_endpoint", "scopes_supported",
	"response_types_supported", "response_modes_supported", "grant_types_supported", "token_endpoint_auth_methods_supported",
	"token_endpoint_auth_signing_alg_values_supported", "service_documentation", "ui_locales_supported", "op_policy_uri", "op_tos_uri",
	"revocation_endpoint", "revocation_endpoint_auth_methods_supported", "revocation_endpoint_auth_signing_alg_values_supported",
	"introspection_endpoint", "introspection_endpoint_auth_methods_supported", "introspection_endpoint_auth_signing_alg_values_supported",
	"code_challenge_methods_supported", "authorization_response_iss_parameter_supported",
}

// TestMetadataResponse checks that the metadata document is a 200 response with an application/json object of metadata values.
//
//conformance:covers RFC8414-3.2-01
func TestMetadataResponse(t *testing.T) {
	a := newAuthorizationServer(t)
	status, header, raw := a.send(http.MethodGet, a.srv.MetadataPath(), "", nil)
	if status != http.StatusOK || header.Get("Content-Type") != "application/json" {
		t.Fatalf("got status %d and Content-Type %q, want 200 and application/json", status, header.Get("Content-Type"))
	}
	names, err := members(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if !slices.Contains(metadataNames, name) {
			t.Fatalf("got member %q, want only metadata values", name)
		}
	}
}

// TestMetadataOmitsEmptyClaims checks that no member of the metadata document is empty or null, also with configured endpoint paths and one scope.
//
//conformance:covers RFC8414-3.2-03
func TestMetadataOmitsEmptyClaims(t *testing.T) {
	a := newConfiguredServer(t, func(c *oauth21.Config) {
		c.Scopes = []string{"read"}
		c.Paths = oauth21.Paths{Authorization: "/oauth/authorize", Token: "/oauth/token"} // #nosec G101 -- endpoint paths, not credentials
	})
	for name, v := range a.metadata(a.url) {
		if values, ok := v.([]any); v == nil || v == "" || ok && len(values) == 0 {
			t.Fatalf("got %s %v, want it omitted", name, v)
		}
	}
}

// TestMetadataIssuerMatchesWellKnownURL checks that the issuer of the metadata document is identical to the issuer its URL was formed from, also with a path and a trailing slash.
//
//conformance:covers RFC8414-3.3-01
func TestMetadataIssuerMatchesWellKnownURL(t *testing.T) {
	for _, path := range []string{"", "/tenant", "/tenant/", "/a/b"} {
		t.Run(path, func(t *testing.T) {
			a := newConfiguredServer(t, func(c *oauth21.Config) { c.Issuer += path })
			if got := a.metadata(a.url + path)["issuer"]; got != a.url+path {
				t.Fatalf("got issuer %v, want %s", got, a.url+path)
			}
		})
	}
}

// TestMetadataListsS256 checks that the metadata lists S256 in code_challenge_methods_supported, so a Client can detect PKCE support.
//
//conformance:covers RFC9700-2.1.1-10
func TestMetadataListsS256(t *testing.T) {
	a := newAuthorizationServer(t)
	methods, _ := a.metadata(a.url)["code_challenge_methods_supported"].([]any)
	if !slices.Contains(methods, any("S256")) {
		t.Fatalf("got code_challenge_methods_supported %v, want S256 in it", methods)
	}
}

// TestListedChallengeMethodsAreAccepted checks that the metadata at the well-known path names the code challenge methods the authorization endpoint accepts.
//
//conformance:covers RFC9700-4.7.1-04
func TestListedChallengeMethodsAreAccepted(t *testing.T) {
	a := newAuthorizationServer(t)
	methods, _ := a.metadata(a.url)["code_challenge_methods_supported"].([]any)
	if len(methods) == 0 {
		t.Fatal("got no code_challenge_methods_supported, want the supported methods")
	}
	for _, m := range methods {
		params := authorizeParams()
		method, _ := m.(string)
		params.Set("code_challenge_method", method)
		if q := a.login(a.authorize(params), "alice").Query(); !q.Has("code") {
			t.Fatalf("%v: got redirect query %v, want a code", m, q)
		}
	}
}

// TestMetadataDocumentsScopes checks that the metadata document lists the configured scopes in scopes_supported.
//
//conformance:covers OAUTH21D16-1.4.1-04
func TestMetadataDocumentsScopes(t *testing.T) {
	a := newConfiguredServer(t, func(c *oauth21.Config) { c.Scopes = []string{"read", "write", "profile", "email"} })
	if got := a.metadata(a.url)["scopes_supported"]; !reflect.DeepEqual(got, []any{"read", "write", "profile", "email"}) {
		t.Fatalf("got scopes_supported %v, want read, write, profile and email", got)
	}
}
