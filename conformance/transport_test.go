package conformance

import (
	"bytes"
	"crypto/tls"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/bearer"
)

// tls12 limits a connection to TLS 1.2.
var tls12 = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12} // #nosec G402 -- the tests check TLS 1.2 support

// rc4 limits a connection to TLS 1.2 with RC4, which does not keep it confidential.
var rc4 = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA}} // #nosec G402 -- the tests check that RC4 is refused

// legacyTLS limits a connection to each TLS version below 1.2.
var legacyTLS = map[string]*tls.Config{
	"TLS 1.0": {MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10}, // #nosec G402 -- the tests check that TLS 1.0 is refused
	"TLS 1.1": {MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11}, // #nosec G402 -- the tests check that TLS 1.1 is refused
}

// wantNoTLS checks that an endpoint error response refuses a request that did not arrive over TLS.
func (a *authorizationServer) wantNoTLS(status int, body map[string]any) {
	a.t.Helper()
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
	if body["error_description"] != "TLS required" {
		a.t.Fatalf("got body %v, want error_description %q", body, "TLS required")
	}
}

// TestTokenEndpointIssuesNoAccessTokenWithoutTLS checks that a token request over plain HTTP gets no access token.
//
//conformance:covers OAUTH21D16-1.4-04
func TestTokenEndpointIssuesNoAccessTokenWithoutTLS(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	a.overPlainHTTP(func() {
		status, _, body := a.token(params, nil)
		a.wantNoTLS(status, body)
	})
}

// TestRefreshRefusedWithoutTLS checks that a refresh request over plain HTTP gets no refresh token.
//
//conformance:covers OAUTH21D16-4.3-06
func TestRefreshRefusedWithoutTLS(t *testing.T) {
	a := newAuthorizationServer(t)
	refresh := a.publicRefreshToken()
	a.overPlainHTTP(func() {
		status, _, body := a.token(refreshParams(refresh), nil)
		a.wantNoTLS(status, body)
	})
}

// TestCredentialsAndTokensRefusedWithoutTLS checks that client secrets and tokens over plain HTTP are refused, whether they are in the content or in a header field.
//
//conformance:covers OAUTH21D16-1.5-01
func TestCredentialsAndTokensRefusedWithoutTLS(t *testing.T) {
	a := newConfiguredServer(t, func(*oauth21.Config) {}, append(newIntrospectionClients(t), serviceClient(t))...)
	a.resource(a.local())
	access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	secretInContent := clientCredentialsParams("")
	secretInContent.Set("client_id", serviceID)
	secretInContent.Set("client_secret", secret)
	a.overPlainHTTP(func() {
		for _, r := range []struct {
			params url.Values
			header http.Header
		}{
			{clientCredentialsParams(""), basic(serviceID, secret)},
			{secretInContent, nil},
			{refreshParams(refresh), nil},
		} {
			status, _, body := a.token(r.params, r.header)
			a.wantNoTLS(status, body)
		}
		a.wantBearerNoTLS(bearerHeader(access))
	})
}

// TestRevocationEndpointRequiresTLS checks that a revocation request over plain HTTP or TLS below 1.2 is refused and leaves the token active.
//
//conformance:covers RFC7009-2-06
func TestRevocationEndpointRequiresTLS(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	revoke := func() {
		status, _, body := a.sendJSON(http.MethodPost, "/revoke", revocationParams(access).Encode(), nil)
		a.wantNoTLS(status, body)
	}
	a.overPlainHTTP(revoke)
	for _, config := range legacyTLS {
		a.overTLS(config, revoke)
	}
	a.wantActive(access)
}

// TestIntrospectionEndpointRequiresTLS checks that an introspection request over plain HTTP or TLS below 1.2 is refused without telling whether the token is active.
//
//conformance:covers RFC7662-2-01
func TestIntrospectionEndpointRequiresTLS(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	introspect := func() {
		status, _, body := a.sendJSON(http.MethodPost, "/introspect", url.Values{"token": {access}}.Encode(), basic(resourceServerID, secret))
		a.wantNoTLS(status, body)
	}
	a.overPlainHTTP(introspect)
	for _, config := range legacyTLS {
		a.overTLS(config, introspect)
	}
}

// TestMetadataServedOnlyOverTLS checks that the metadata endpoint answers over TLS and refuses plain HTTP.
//
//conformance:covers RFC8414-6.1-01
func TestMetadataServedOnlyOverTLS(t *testing.T) {
	a := newAuthorizationServer(t)
	a.metadata(a.url)
	a.overPlainHTTP(func() {
		status, _, body := a.sendJSON(http.MethodGet, a.srv.MetadataPath(), "", nil)
		a.wantNoTLS(status, body)
	})
}

// TestMetadataServedOverTLS12 checks that the metadata endpoint answers over TLS 1.2.
//
//conformance:covers RFC8414-6.1-02
func TestMetadataServedOverTLS12(t *testing.T) {
	a := newAuthorizationServer(t)
	a.overTLS(tls12, func() { a.metadata(a.url) })
}

// TestIntrospectionOverTLS12 checks that the introspection endpoint answers over TLS 1.2.
//
//conformance:covers RFC7662-4-11
func TestIntrospectionOverTLS12(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.overTLS(tls12, func() { a.wantActive(access) })
}

// TestMetadataRefusesCipherSuiteWithoutConfidentiality checks that the metadata endpoint answers over TLS with AES-GCM and refuses RC4, which does not keep the request confidential.
//
//conformance:covers RFC8414-6.1-05
func TestMetadataRefusesCipherSuiteWithoutConfidentiality(t *testing.T) {
	a := newAuthorizationServer(t)
	gcm := tls12.Clone()
	gcm.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	a.overTLS(gcm, func() { a.metadata(a.url) })
	a.overTLS(rc4, func() {
		status, _, body := a.sendJSON(http.MethodGet, a.srv.MetadataPath(), "", nil)
		a.wantNoTLS(status, body)
	})
}

// TestAuthorizationResponseOnlyOverTLS checks that the authorization endpoint answers plain HTTP with an error page instead of the redirects it sends over TLS, for a valid request and for one with an unknown scope.
//
//conformance:covers RFC9700-2.6-04
func TestAuthorizationResponseOnlyOverTLS(t *testing.T) {
	a := newAuthorizationServer(t)
	unknown := authorizeParams()
	unknown.Set("scope", "unknown")
	a.pending(a.authorize(authorizeParams()))
	a.wantAuthorizationError(a.authorize(unknown), "invalid_scope", "")
	a.overPlainHTTP(func() {
		for _, params := range []url.Values{authorizeParams(), unknown} {
			status, header, _ := a.send(http.MethodGet, "/authorize?"+params.Encode(), "", nil)
			if status != http.StatusBadRequest || header.Get("Location") != "" {
				t.Fatalf("got status %d and Location %q for %v, want 400 without a redirect", status, header.Get("Location"), params)
			}
		}
	})
}

// forwardedHTTPS are the headers of a proxy that received a request over TLS.
var forwardedHTTPS = []http.Header{
	{"X-Forwarded-Proto": {"https"}},
	{"Forwarded": {"proto=https"}},
}

// TestForwardedHeadersNotTrusted checks that every endpoint and the bearer middleware refuse a request over plain HTTP whose headers claim it reached a proxy over TLS.
//
//conformance:covers INV-0016
func TestForwardedHeadersNotTrusted(t *testing.T) {
	a := newServiceServer(t)
	a.resource(a.local())
	p := a.srv.Paths()
	endpoints := []struct{ method, path, form string }{
		{http.MethodPost, p.Token, clientCredentialsParams("").Encode()},
		{http.MethodPost, p.Revocation, url.Values{"token": {"token"}}.Encode()},
		{http.MethodPost, p.Introspection, url.Values{"token": {"token"}}.Encode()},
		{http.MethodGet, a.srv.MetadataPath(), ""},
	}
	a.overPlainHTTP(func() {
		for _, forwarded := range forwardedHTTPS {
			for _, e := range endpoints {
				h := basic(serviceID, secret)
				maps.Copy(h, forwarded)
				status, _, body := a.sendJSON(e.method, e.path, e.form, h)
				a.wantNoTLS(status, body)
			}
			status, header, body := a.send(http.MethodGet, p.Authorization+"?"+authorizeParams().Encode(), "", forwarded)
			if status != http.StatusBadRequest || header.Get("Location") != "" || string(body) != "invalid_request: TLS required\n" {
				t.Fatalf("got status %d, Location %q and body %q from the authorization endpoint, want its TLS required page", status, header.Get("Location"), body)
			}
			a.wantBearerNoTLS(forwarded)
		}
	})
}

// TestOtherSecureTransportDeclaredByHostApplication checks that the metadata endpoint and the bearer middleware answer plain HTTP over a transport the Host Application declares secure, such as a VPN.
//
//conformance:covers OAUTH21D16-1.5-05
func TestOtherSecureTransportDeclaredByHostApplication(t *testing.T) {
	vpn := func(*http.Request) bool { return true }
	a := newConfiguredServer(t, func(c *oauth21.Config) { c.Secure = vpn }, newIntrospectionClients(t)...)
	a.protect(bearer.SecureMiddleware(vpn, a.local()))
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.overPlainHTTP(func() {
		a.metadata(a.url)
		a.wantAccess(access, http.StatusOK)
	})
}

// wantBearerNoTLS checks that a request with header to the protected resource is refused for not arriving over TLS.
func (a *authorizationServer) wantBearerNoTLS(header http.Header) {
	a.t.Helper()
	a.wantChallenge(header, http.StatusBadRequest, `Bearer realm="oauth21", error="invalid_request", error_description="TLS required"`)
}

// TestBearerTokenNotUsedWithoutTLS checks that the bearer middleware refuses a request over plain HTTP before validating its access token.
//
//conformance:covers OAUTH21D16-1.4.2-01
func TestBearerTokenNotUsedWithoutTLS(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		before := len(a.recorder.keys())
		a.overPlainHTTP(func() { a.wantBearerNoTLS(bearerHeader(access)) })
		if keys := a.recorder.keys()[before:]; slices.ContainsFunc(keys, func(k []byte) bool { return bytes.Equal(k, hashOf(access)) }) {
			t.Fatal("got the access token validated, want it refused before")
		}
	})
}

// TestResourceServedOnlyAtHTTPSURL checks that a protected resource answers at its https URL and refuses its http URL.
//
//conformance:covers OAUTH21D16-1.5-06
func TestResourceServedOnlyAtHTTPSURL(t *testing.T) {
	a := newIntrospectionServer(t)
	a.resource(a.local())
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.wantAccess(access, http.StatusOK)
	a.overPlainHTTP(func() { a.wantBearerNoTLS(bearerHeader(access)) })
}

// TestBearerRequiresTLSToResourceServer checks that the bearer middleware refuses a request that reached a TLS-terminating proxy in front of it and went on over plain HTTP.
//
//conformance:covers OAUTH21D16-1.4.3-02
func TestBearerRequiresTLSToResourceServer(t *testing.T) {
	a := newIntrospectionServer(t)
	a.resource(a.local())
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.behindTLSProxy(func() { a.wantBearerNoTLS(bearerHeader(access)) })
}

// TestBearerRequiresEndToEndTLSPerBCP195 checks that the bearer middleware refuses a request whose TLS ended at a proxy in front of it, or that arrived over TLS 1.0, TLS 1.1 or RC4, which BCP 195 does not allow.
//
//conformance:covers RFC9700-2.6-03
func TestBearerRequiresEndToEndTLSPerBCP195(t *testing.T) {
	a := newIntrospectionServer(t)
	a.resource(a.local())
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.behindTLSProxy(func() { a.wantBearerNoTLS(bearerHeader(access)) })
	configs := maps.Clone(legacyTLS)
	configs["RC4"] = rc4
	for _, config := range configs {
		a.overTLS(config, func() { a.wantBearerNoTLS(bearerHeader(access)) })
	}
}

// TestRemoteSendsNoTokenWithoutTLS checks that the remote validator does not send an access token to an introspection endpoint with an http URL.
//
//conformance:covers RFC9700-4.9.3-04
func TestRemoteSendsNoTokenWithoutTLS(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	var sent atomic.Bool
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sent.Store(true) }))
	defer plain.Close()
	r := a.remote(resourceServerID, secret)
	r.Endpoint, r.Client = plain.URL+a.srv.Paths().Introspection, plain.Client()
	if _, err := r.Validate(t.Context(), access); err == nil || sent.Load() {
		t.Fatalf("got error %v and the token sent %t, want an error without sending it", err, sent.Load())
	}
}
