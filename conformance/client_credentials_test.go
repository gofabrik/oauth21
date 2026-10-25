package conformance

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/gofabrik/oauth21/store"
)

const serviceID = "service"

// newServiceServer starts an Authorization Server with the confidential Client and the service Client, which may use client credentials.
func newServiceServer(t *testing.T) *authorizationServer {
	t.Helper()
	return newAuthorizationServer(t, serviceClients(t)...)
}

// serviceClients returns the confidential Client and the service Client, which may use client credentials.
func serviceClients(t *testing.T) []store.Client {
	t.Helper()
	service := confidentialClient(t)
	service.ID = serviceID
	service.RedirectURIs = nil
	service.AllowedScopes = []string{"read", "write"}
	service.GrantTypes = []string{"client_credentials"}
	return []store.Client{confidentialClient(t), service}
}

// clientCredentialsParams returns a client credentials request asking for scope, or the default scopes when it is empty.
func clientCredentialsParams(scope string) url.Values {
	params := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		params.Set("scope", scope)
	}
	return params
}

// TestClientCredentialsIssuesAccessToken checks that a confidential Client allowed the grant type gets an access token and no refresh token.
func TestClientCredentialsIssuesAccessToken(t *testing.T) {
	for name, authenticate := range map[string]func(url.Values) http.Header{
		"client_secret_basic": func(url.Values) http.Header { return basic(serviceID, secret) },
		"client_secret_post": func(params url.Values) http.Header {
			params.Set("client_id", serviceID)
			params.Set("client_secret", secret)
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := newServiceServer(t)
			params := clientCredentialsParams("")
			status, _, body := a.token(params, authenticate(params))
			if status != http.StatusOK || body["access_token"] == nil || body["token_type"] != "Bearer" || body["scope"] != "read" || body["expires_in"] != float64(3600) {
				t.Fatalf("got status %d and body %v, want a Bearer access token with scope read for an hour", status, body)
			}
			if _, ok := body["refresh_token"]; ok {
				t.Fatalf("got body %v, want no refresh token", body)
			}
		})
	}
}

// TestClientCredentialsRequiresConfidentialClient checks that a public Client gets unauthorized_client even when allowed the grant type.
//
//conformance:covers OAUTH21D16-4.2-01
func TestClientCredentialsRequiresConfidentialClient(t *testing.T) {
	a := newAuthorizationServer(t, store.Client{ID: "public service", Type: store.Public, AllowedScopes: readScope, DefaultScopes: readScope, GrantTypes: []string{"client_credentials"}})
	params := clientCredentialsParams("")
	params.Set("client_id", "public service")
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "unauthorized_client")
}

// TestClientCredentialsRequiresAllowedGrantType checks that a confidential Client not allowed the grant type gets unauthorized_client.
func TestClientCredentialsRequiresAllowedGrantType(t *testing.T) {
	a := newServiceServer(t)
	status, _, body := a.token(clientCredentialsParams(""), basic(confidentialID, secret))
	a.wantOAuthError(status, body, http.StatusBadRequest, "unauthorized_client")
}

// TestClientCredentialsRequiresAuthentication checks that a client credentials request with a wrong secret gets invalid_client.
//
//conformance:covers OAUTH21D16-4.2.1-02
func TestClientCredentialsRequiresAuthentication(t *testing.T) {
	a := newServiceServer(t)
	status, _, body := a.token(clientCredentialsParams(""), basic(serviceID, "wrong"))
	a.wantOAuthError(status, body, http.StatusUnauthorized, "invalid_client")
}

// TestClientCredentialsScopes checks that a client credentials request gets the requested scopes only when they are supported and allowed for the Client.
//
//conformance:covers INV-0003
func TestClientCredentialsScopes(t *testing.T) {
	a := newServiceServer(t)
	status, _, body := a.token(clientCredentialsParams("write read"), basic(serviceID, secret))
	if status != http.StatusOK || body["scope"] != "write read" {
		t.Fatalf("got status %d and body %v, want scope write read", status, body)
	}
	for _, scope := range []string{"read admin", "read delete"} {
		status, _, body := a.token(clientCredentialsParams(scope), basic(serviceID, secret))
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_scope")
	}
}

// TestClientCredentialsWithoutScopeOrDefaultsFails checks that a client credentials request without scope fails with invalid_scope for a Client without default scopes.
//
//conformance:covers INV-0003
func TestClientCredentialsWithoutScopeOrDefaultsFails(t *testing.T) {
	service := confidentialClient(t)
	service.DefaultScopes = nil
	service.GrantTypes = []string{"client_credentials"}
	a := newAuthorizationServer(t, service)
	status, _, body := a.token(clientCredentialsParams(""), basic(confidentialID, secret))
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_scope")
}
