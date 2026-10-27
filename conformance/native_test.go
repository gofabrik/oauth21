package conformance

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/gofabrik/oauth21/store"
)

const (
	nativeID          = "native"
	nativeRedirectURI = "http://127.0.0.1/cb"
)

// nativeClient returns the public native app Client with a loopback redirect URI.
func nativeClient() store.Client {
	return publicClient(nativeID, nativeRedirectURI)
}

// nativeParams returns a valid authorization request of the native app Client.
func nativeParams() url.Values {
	params := authorizeParams()
	params.Set("client_id", nativeID)
	params.Set("redirect_uri", nativeRedirectURI)
	return params
}

// nativeClientWithSecret returns the native app Client registered as public with a secret, allowed client credentials and introspection.
func nativeClientWithSecret(t *testing.T) store.Client {
	t.Helper()
	native := nativeClient()
	native.SecretHash = confidentialClient(t).SecretHash
	native.GrantTypes = []string{"authorization_code", "refresh_token", "client_credentials"}
	native.Introspect = true
	return native
}

// TestNativeAppRedeemsCodeWithoutSecret checks that a native app redeems its code with its client_id alone.
//
//conformance:covers OAUTH21D16-8.1-01
func TestNativeAppRedeemsCodeWithoutSecret(t *testing.T) {
	a := newAuthorizationServer(t, nativeClient())
	a.tokens(a.nativeTokenParams(nativeID, nativeRedirectURI), nil)
}

// TestNativeAppRefreshesWithoutSecret checks that a native app refreshes its tokens with its client_id alone.
//
//conformance:covers RFC8252-8.5-01
func TestNativeAppRefreshesWithoutSecret(t *testing.T) {
	a := newAuthorizationServer(t, nativeClient())
	refresh := a.refreshToken(a.nativeTokenParams(nativeID, nativeRedirectURI), nil)
	params := refreshParams(refresh)
	params.Set("client_id", nativeID)
	a.tokens(params, nil)
}

// TestNativeAppSecretIsNotProofForClientCredentials checks that a native app registered as public with a secret cannot use client credentials with that secret.
//
//conformance:covers OAUTH21D16-8.1-02
func TestNativeAppSecretIsNotProofForClientCredentials(t *testing.T) {
	a := newAuthorizationServer(t, nativeClientWithSecret(t))
	for name, authenticate := range map[string]func(url.Values) http.Header{
		"client_secret_basic": func(url.Values) http.Header { return basic(nativeID, secret) },
		"client_secret_post": func(params url.Values) http.Header {
			params.Set("client_id", nativeID)
			params.Set("client_secret", secret)
			return nil
		},
	} {
		params := clientCredentialsParams("")
		if status, _, body := a.token(params, authenticate(params)); status == http.StatusOK || body["access_token"] != nil {
			t.Fatalf("%s: got status %d and body %v, want no access token", name, status, body)
		}
	}
}

// TestNativeAppSecretIsNotProofForIntrospection checks that a native app registered as public with a secret cannot introspect with that secret.
//
//conformance:covers RFC8252-8.5-02
func TestNativeAppSecretIsNotProofForIntrospection(t *testing.T) {
	a := newAuthorizationServer(t, nativeClientWithSecret(t))
	access, _ := a.tokens(a.nativeTokenParams(nativeID, nativeRedirectURI), nil)
	a.wantIntrospectionError(url.Values{"token": {access}}, basic(nativeID, secret), http.StatusUnauthorized, "invalid_client")
}
