package conformance

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/gofabrik/oauth21/store"
)

// TestClientWithoutTypeIsRefused checks that the authorization endpoint refuses a Client registered without a known type.
//
//conformance:covers OAUTH21D16-2-01
func TestClientWithoutTypeIsRefused(t *testing.T) {
	for _, typ := range []store.ClientType{0, store.Public + 1} {
		c := publicClient("untyped", redirectURI)
		c.Type = typ
		a := newAuthorizationServer(t, c)
		params := authorizeParams()
		params.Set("client_id", "untyped")
		a.wantNoRedirect(params)
	}
}

// TestServerAssumesNoClientType checks that a Client registered without a type is neither authenticated as a confidential Client nor identified as a public one.
//
//conformance:covers RFC6749-2.1-01
func TestServerAssumesNoClientType(t *testing.T) {
	untyped := serviceClient(t)
	untyped.Type = 0
	a := newAuthorizationServer(t, untyped)
	status, _, body := a.token(clientCredentialsParams(""), basic(serviceID, secret))
	a.wantOAuthError(status, body, http.StatusUnauthorized, "invalid_client")
	params := clientCredentialsParams("")
	params.Set("client_id", serviceID)
	status, _, body = a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
}

// TestClientHasOneType checks that a Client is treated only as its registered type: a public Client holding a secret hash cannot authenticate with the secret, and a confidential Client cannot redeem a code with only its client_id.
//
//conformance:covers OAUTH21D16-2.1-03
func TestClientHasOneType(t *testing.T) {
	confidential := confidentialClient(t)
	public := confidential
	public.ID, public.Type = "public-with-secret", store.Public
	a := newAuthorizationServer(t, confidential, public)
	params := authorizeParams()
	params.Set("client_id", public.ID)
	token := tokenParams(a.code(params))
	token.Del("client_id")
	status, _, body := a.token(token, basic(public.ID, secret))
	a.wantOAuthError(status, body, http.StatusUnauthorized, "invalid_client")
	token = a.confidentialCode()
	token.Set("client_id", confidentialID)
	status, _, body = a.token(token, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
}

// nativeRequest returns a valid authorization request of the native app Client for uri.
func nativeRequest(uri string) url.Values {
	params := nativeParams()
	params.Set("redirect_uri", uri)
	return params
}

// namedAndOmittedRequests returns authorization requests of the native app Client, one naming uri and one omitting redirect_uri.
func namedAndOmittedRequests(uri string) []url.Values {
	omitted := nativeParams()
	omitted.Del("redirect_uri")
	return []url.Values{nativeRequest(uri), omitted}
}

// wantRedirectURINotUsed checks that a public Client registering only uri is not redirected to it.
func wantRedirectURINotUsed(t *testing.T, uri string) {
	t.Helper()
	a := newAuthorizationServer(t, publicClient(nativeID, uri))
	for _, params := range namedAndOmittedRequests(uri) {
		a.wantNoRedirect(params)
	}
}

// TestRegisteredRedirectURIMustBeAbsolute checks that a registered redirect URI that is relative or not a URI is not used.
//
//conformance:covers OAUTH21D16-2.3-01
func TestRegisteredRedirectURIMustBeAbsolute(t *testing.T) {
	for _, uri := range []string{
		"/cb", "client.example/cb", "//client.example/cb", "",
		"https://client.example/a b", `https://client.example/a"<>`, "https://client.example/^{}", "com.example.app:a b", "https://client.example/\u00e9",
		"https://client.example/cb?a=%zz", "https://client.example/cb?a=%2",
		"https://client.example/[x]",
		"com.example.app://a@b@h/cb",
		"com.example.app://a:b:80/cb", "com.example.app://::1/cb",
	} {
		wantRedirectURINotUsed(t, uri)
	}
}

// TestRegisteredRedirectURIHasNoFragment checks that a registered redirect URI with a fragment component, an empty one included, is not used.
//
//conformance:covers OAUTH21D16-2.3-04
func TestRegisteredRedirectURIHasNoFragment(t *testing.T) {
	for _, uri := range []string{redirectURI + "#frag", redirectURI + "#", "http://127.0.0.1/cb#x", "com.example.app:/cb#"} {
		wantRedirectURINotUsed(t, uri)
	}
}

// TestHTTPRedirectURIOnlyForLoopback checks that a registered http redirect URI other than a loopback IP one is not used.
//
//conformance:covers RFC9700-2.6-05
func TestHTTPRedirectURIOnlyForLoopback(t *testing.T) {
	for _, uri := range []string{"http://localhost/cb", "http://10.0.0.1/cb", "http://127.0.0.1.example/cb", "http://client.example:8080/cb"} {
		wantRedirectURINotUsed(t, uri)
	}
}

// TestPrivateUseSchemeIsReverseDomainName checks that a registered private-use URI scheme redirect URI is used only when its scheme is a reverse domain name.
//
//conformance:covers OAUTH21D16-2.3.1-04
func TestPrivateUseSchemeIsReverseDomainName(t *testing.T) {
	for _, uri := range []string{"com.:/cb", "com..app:/cb", "com.exa+mple:/cb"} {
		wantRedirectURINotUsed(t, uri)
	}
	a := newAuthorizationServer(t, publicClient(nativeID, "com.example.app:/cb"))
	a.nativeCode(nativeID, "com.example.app:/cb")
}

// TestPrivateUseSchemeWithoutPeriodIsNotUsed checks that a registered private-use URI scheme redirect URI whose scheme has no period is not used.
//
//conformance:covers OAUTH21D16-2.3.1-05
func TestPrivateUseSchemeWithoutPeriodIsNotUsed(t *testing.T) {
	for _, uri := range []string{"myapp:/cb", "javascript:/cb"} {
		wantRedirectURINotUsed(t, uri)
	}
}

// TestNativePrivateUseSchemeIsReverseDomainName checks that a registered private-use URI scheme redirect URI is used only when its scheme is a reverse domain name based on a domain name.
//
//conformance:covers RFC8252-8.4-04
func TestNativePrivateUseSchemeIsReverseDomainName(t *testing.T) {
	for _, uri := range []string{"com.example.:/oauth2redirect", "com+example.app:/oauth2redirect", "com.-.app:/oauth2redirect"} {
		wantRedirectURINotUsed(t, uri)
	}
	a := newAuthorizationServer(t, publicClient(nativeID, "io.github.app-name:/oauth2redirect"))
	a.nativeCode(nativeID, "io.github.app-name:/oauth2redirect")
}

// TestNativePrivateUseSchemeWithoutPeriodIsNotUsed checks that a registered native app redirect URI with a private-use URI scheme without a period is not used.
//
//conformance:covers RFC8252-8.4-05
func TestNativePrivateUseSchemeWithoutPeriodIsNotUsed(t *testing.T) {
	for _, uri := range []string{"exampleapp:/oauth2redirect", "x-app:/oauth2redirect", "urn:ietf:wg:oauth:2.0:oob"} {
		wantRedirectURINotUsed(t, uri)
	}
}

// TestRegisteredRedirectURIIsComplete checks that a registered redirect URI with an empty path is used as it is and does not match a request that adds a path.
//
//conformance:covers RFC8252-8.4-03
func TestRegisteredRedirectURIIsComplete(t *testing.T) {
	a := newAuthorizationServer(t, publicClient(nativeID, "https://app.example", "http://127.0.0.1", "com.example.app:"))
	for _, uri := range []string{"https://app.example/cb", "http://127.0.0.1:51004/cb", "com.example.app:/cb"} {
		a.wantNoRedirect(nativeRequest(uri))
	}
	a.nativeCode(nativeID, "https://app.example")
	a.nativeCode(nativeID, "http://127.0.0.1:51004")
	a.nativeCode(nativeID, "com.example.app:")
}

// TestClientWithoutRedirectURIGetsNoCode checks that the authorization code grant is refused to a Client that registered no redirect URI.
//
//conformance:covers OAUTH21D16-2-02
func TestClientWithoutRedirectURIGetsNoCode(t *testing.T) {
	a := newAuthorizationServer(t, publicClient(nativeID))
	for _, params := range namedAndOmittedRequests(redirectURI) {
		a.wantNoRedirect(params)
	}
}
