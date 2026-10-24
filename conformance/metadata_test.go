package conformance

import (
	"net/http"
	"net/url"
	"reflect"
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
