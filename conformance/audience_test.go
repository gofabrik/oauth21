package conformance

import (
	"maps"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/bearer"
)

// consentedCode returns the code of the authorization request params that alice completes with scope read and audience.
func (a *authorizationServer) consentedCode(params url.Values, audience ...string) string {
	a.t.Helper()
	req := a.pending(a.authorize(params))
	return a.complete(req.ID, oauth21.Completion{Subject: "alice", Scopes: readScope, Audience: audience}).Query().Get("code")
}

// consentedTokens returns the access and refresh tokens of a code of the Client id that alice completed with audience.
func (a *authorizationServer) consentedTokens(id string, audience ...string) (access, refresh string) {
	a.t.Helper()
	params := authorizeParams()
	params.Set("client_id", id)
	token := tokenParams(a.consentedCode(params, audience...))
	if id != confidentialID {
		return a.tokens(token, nil)
	}
	token.Del("client_id")
	return a.tokens(token, basic(confidentialID, secret))
}

// withAudienceParams returns a copy of params whose audience parameters name the other Resource Server.
func withAudienceParams(params url.Values) url.Values {
	p := maps.Clone(params)
	for _, name := range []string{"resource", "audience", "aud"} {
		p.Set(name, otherResourceServerID)
	}
	return p
}

// wantAudience checks that token introspects as active with audience want.
func (a *authorizationServer) wantAudience(token string, want ...string) {
	a.t.Helper()
	body := a.introspect(token)
	var got []string
	switch aud := body["aud"].(type) {
	case string:
		got = []string{aud}
	case []any:
		for _, v := range aud {
			s, _ := v.(string)
			got = append(got, s)
		}
	}
	if body["active"] != true || !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) {
		a.t.Fatalf("got %v, want an active token with audience %q", body, want)
	}
}

// resources serves /documents with scope read and /admin with scope admin on the Resource Server Client, and the same under /other on the other Resource Server.
func (a *authorizationServer) resources() {
	for prefix, id := range map[string]string{"": resourceServerID, "/other": otherResourceServerID} {
		v := bearer.Local{Tokens: a.recorder, ClientID: id, Clock: a.now}
		for path, scope := range map[string]string{"/documents": "read", "/admin": "admin"} {
			a.mux.Handle(prefix+path, bearer.Middleware(v, scope)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
		}
	}
}

// TestAccessTokenIsRestrictedToConsentedResourceServers checks that an access token has exactly the one or few Resource Servers consented to as its audience.
//
//conformance:covers RFC9700-2.3-02
func TestAccessTokenIsRestrictedToConsentedResourceServers(t *testing.T) {
	a := newIntrospectionServer(t)
	for _, audience := range [][]string{{resourceServerID}, {resourceServerID, otherResourceServerID}} {
		access, _ := a.consentedTokens(clientID, audience...)
		a.wantAudience(access, audience...)
	}
}

// TestClientCannotWidenConsentedAudience checks that audience parameters in the authorization and token requests do not change the consented audience.
//
//conformance:covers RFC9700-4.10-02
func TestClientCannotWidenConsentedAudience(t *testing.T) {
	a := newIntrospectionServer(t)
	code := a.consentedCode(withAudienceParams(authorizeParams()), resourceServerID)
	access, _ := a.tokens(withAudienceParams(tokenParams(code)), nil)
	a.wantAudience(access, resourceServerID)
}

// TestConsentedAudiencePreventsReplay checks that a Resource Server refuses an access token of a Grant consented only to another Resource Server.
//
//conformance:covers RFC9700-4.9.3-02
func TestConsentedAudiencePreventsReplay(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		access, _ := a.consentedTokens(clientID, resourceServerID)
		a.wantAccess(access, http.StatusOK)
		captured, _ := a.consentedTokens(clientID, otherResourceServerID)
		a.wantAccess(captured, http.StatusUnauthorized)
	})
}

// TestTokenIsRestrictedToResources checks that an access token is served only by the resources of its scopes on its consented Resource Server.
//
//conformance:covers OAUTH21D16-7.1.4-08
func TestTokenIsRestrictedToResources(t *testing.T) {
	a := newIntrospectionServer(t)
	a.resources()
	access, _ := a.consentedTokens(clientID, resourceServerID)
	a.wantRoute(access, "/documents", http.StatusOK)
	a.wantRoute(access, "/admin", http.StatusForbidden)
	a.wantRoute(access, "/other/documents", http.StatusUnauthorized)
}

// TestConfidentialClientTokenIsRestrictedToResources checks that an access token of the confidential Client is served only by the resources of its scopes on its consented Resource Server.
//
//conformance:covers RFC9700-2.3-12
func TestConfidentialClientTokenIsRestrictedToResources(t *testing.T) {
	a := newIntrospectionServer(t)
	a.resources()
	access, _ := a.consentedTokens(confidentialID, otherResourceServerID)
	a.wantRoute(access, "/other/documents", http.StatusOK)
	a.wantRoute(access, "/other/admin", http.StatusForbidden)
	a.wantRoute(access, "/documents", http.StatusUnauthorized)
}

// TestRefreshedAccessTokenHasConsentedAudience checks that a refresh token of the public Client, refreshed twice with audience parameters, issues access tokens with the consented audience.
//
//conformance:covers RFC9700-4.14.2-08
func TestRefreshedAccessTokenHasConsentedAudience(t *testing.T) {
	a := newIntrospectionServer(t)
	_, refresh := a.consentedTokens(clientID, resourceServerID)
	params := func(refresh string) url.Values { return withAudienceParams(refreshParams(refresh)) }
	for _, access := range a.successiveAccessTokens(refresh, params, nil) {
		a.wantAudience(access, resourceServerID)
	}
}
