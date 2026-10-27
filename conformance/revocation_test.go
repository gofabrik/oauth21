package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofabrik/oauth21"
)

// revocationParams returns a revocation request of the public Client for token.
func revocationParams(token string) url.Values {
	return url.Values{"token": {token}, "client_id": {clientID}}
}

// revoke sends a revocation request with header that must succeed.
func (a *authorizationServer) revoke(params url.Values, header http.Header) {
	a.t.Helper()
	if status, _, body := a.send(http.MethodPost, "/revoke", params.Encode(), header); status != http.StatusOK {
		a.t.Fatalf("got status %d and body %s, want 200", status, body)
	}
}

// wantRevocationError checks that a revocation request with header fails with wantStatus and code.
func (a *authorizationServer) wantRevocationError(params url.Values, header http.Header, wantStatus int, code string) {
	a.t.Helper()
	status, _, body := a.sendJSON(http.MethodPost, "/revoke", params.Encode(), header)
	a.wantOAuthError(status, body, wantStatus, code)
}

// TestRevokedRefreshTokenCannotRefresh checks that a revoked refresh token, and every other refresh token of its Grant, can no longer refresh.
//
//conformance:covers OAUTH21D16-4.3.1-08
func TestRevokedRefreshTokenCannotRefresh(t *testing.T) {
	a := newAuthorizationServer(t)
	first := a.publicRefreshToken()
	second := a.refreshToken(refreshParams(first), nil)
	a.revoke(revocationParams(first), nil)
	status, _, body := a.token(refreshParams(second), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestRevokedGrantHasNoValidToken checks that revoking a refresh token makes every access token and refresh token of its Grant invalid, also those issued by earlier refreshes.
//
//conformance:covers INV-0012
func TestRevokedGrantHasNoValidToken(t *testing.T) {
	a := newIntrospectionServer(t)
	access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	accessTokens := []string{access}
	for range 2 {
		access, refresh = a.tokens(refreshParams(refresh), nil)
		accessTokens = append(accessTokens, access)
	}
	a.revoke(revocationParams(refresh), nil)
	for _, access := range accessTokens {
		a.wantInactive(access)
	}
	status, _, body := a.token(refreshParams(refresh), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestCodeReplayLeavesNoValidToken checks that the Grant a replayed code revokes keeps no valid access token or refresh token, also those issued by a refresh.
//
//conformance:covers INV-0012
func TestCodeReplayLeavesNoValidToken(t *testing.T) {
	a := newIntrospectionServer(t)
	redemption := tokenParams(a.code(authorizeParams()))
	first, refresh := a.tokens(redemption, nil)
	second, refresh := a.tokens(refreshParams(refresh), nil)
	if status, _, _ := a.token(redemption, nil); status != http.StatusBadRequest {
		t.Fatalf("got status %d for a replay, want 400", status)
	}
	a.wantInactive(first)
	a.wantInactive(second)
	status, _, body := a.token(refreshParams(refresh), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestRefreshDuringRevocationIssuesNoValidToken checks that a refresh whose Grant is revoked after its refresh token rotated leaves no valid access token or refresh token.
//
//conformance:covers INV-0013
func TestRefreshDuringRevocationIssuesNoValidToken(t *testing.T) {
	a := newIntrospectionServer(t)
	refresh := a.publicRefreshToken()
	var revoked int
	var err error
	a.recorder.afterRotation(func() {
		revoked, _, _, err = a.trySend(http.MethodPost, "/revoke", revocationParams(refresh).Encode(), nil)
	})
	_, _, body := a.token(refreshParams(refresh), nil)
	if err != nil {
		t.Fatal(err)
	}
	if revoked != http.StatusOK {
		t.Fatalf("got status %d for the revocation, want 200", revoked)
	}
	if access, _ := body["access_token"].(string); access != "" {
		a.wantInactive(access)
	}
	if next, _ := body["refresh_token"].(string); next != "" {
		status, _, body := a.token(refreshParams(next), nil)
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	}
}

// TestRevokedAccessTokenKeepsRefreshToken checks that revoking an access token, with a token_type_hint that does not match, leaves the refresh token of its Grant usable.
func TestRevokedAccessTokenKeepsRefreshToken(t *testing.T) {
	a := newAuthorizationServer(t)
	access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	params := revocationParams(access)
	params.Set("token_type_hint", "refresh_token")
	a.revoke(params, nil)
	a.tokens(refreshParams(refresh), nil)
}

// TestRevokingInvalidTokenSucceeds checks that revoking an unknown, expired or already revoked token succeeds, also for an expired token of another Client.
func TestRevokingInvalidTokenSucceeds(t *testing.T) {
	a := newConfiguredServer(t, func(c *oauth21.Config) { c.RefreshTokenLifetime = time.Hour }, confidentialClient(t))
	a.revoke(revocationParams("unknown"), nil)
	revoked := a.publicRefreshToken()
	a.revoke(revocationParams(revoked), nil)
	a.revoke(revocationParams(revoked), nil)
	access, expired := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.advance(time.Hour)
	a.revoke(url.Values{"token": {expired}}, basic(confidentialID, secret))
	a.revoke(revocationParams(expired), nil)
	a.revoke(revocationParams(access), nil)
}

// TestConfidentialRevocationRequiresAuthentication checks that a confidential Client must authenticate to revoke its token.
func TestConfidentialRevocationRequiresAuthentication(t *testing.T) {
	a := newConfidentialServer(t)
	refresh := a.confidentialRefreshToken()
	params := url.Values{"token": {refresh}, "client_id": {confidentialID}}
	a.wantRevocationError(params, nil, http.StatusBadRequest, "invalid_client")
	params.Del("client_id")
	a.wantRevocationError(params, basic(confidentialID, "wrong"), http.StatusUnauthorized, "invalid_client")
	a.refreshToken(confidentialRefreshParams(refresh), basic(confidentialID, secret))
}

// TestConfidentialClientRevokes checks that a confidential Client revokes its refresh token with client_secret_basic or client_secret_post.
func TestConfidentialClientRevokes(t *testing.T) {
	t.Run("client_secret_basic", func(t *testing.T) {
		a := newConfidentialServer(t)
		refresh := a.confidentialRefreshToken()
		a.revoke(url.Values{"token": {refresh}}, basic(confidentialID, secret))
		status, _, body := a.token(confidentialRefreshParams(refresh), basic(confidentialID, secret))
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	})
	t.Run("client_secret_post", func(t *testing.T) {
		a := newConfidentialServer(t)
		refresh := a.confidentialRefreshToken()
		a.revoke(url.Values{"token": {refresh}, "client_id": {confidentialID}, "client_secret": {secret}}, nil)
		status, _, body := a.token(confidentialRefreshParams(refresh), basic(confidentialID, secret))
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	})
}

// TestRevocationOfAnotherClientsTokenFails checks that a Client cannot revoke a token issued to another Client.
func TestRevocationOfAnotherClientsTokenFails(t *testing.T) {
	a := newConfidentialServer(t)
	refresh := a.publicRefreshToken()
	a.wantRevocationError(url.Values{"token": {refresh}}, basic(confidentialID, secret), http.StatusBadRequest, "invalid_grant")
	a.tokens(refreshParams(refresh), nil)
}

// TestRevocationRequiresToken checks that a revocation request without a token fails with invalid_request.
//
//conformance:covers RFC7009-2.1-01
func TestRevocationRequiresToken(t *testing.T) {
	a := newAuthorizationServer(t)
	a.wantRevocationError(url.Values{"client_id": {clientID}}, nil, http.StatusBadRequest, "invalid_request")
	a.wantRevocationError(url.Values{"client_id": {clientID}, "token": {""}}, nil, http.StatusBadRequest, "invalid_request")
}

// TestRevocationRequiresPost checks that a revocation request not sent with POST fails with invalid_request.
func TestRevocationRequiresPost(t *testing.T) {
	a := newAuthorizationServer(t)
	status, _, body := a.sendJSON(http.MethodGet, "/revoke?"+revocationParams("unknown").Encode(), "", nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestRefreshTokenRevocation checks that a revoked refresh token, of a public or a confidential Client, can no longer refresh.
//
//conformance:covers RFC7009-2-01
func TestRefreshTokenRevocation(t *testing.T) {
	a := newConfidentialServer(t)
	public := a.publicRefreshToken()
	a.revoke(revocationParams(public), nil)
	status, _, body := a.token(refreshParams(public), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	confidential := a.confidentialRefreshToken()
	a.revoke(url.Values{"token": {confidential}}, basic(confidentialID, secret))
	status, _, body = a.token(confidentialRefreshParams(confidential), basic(confidentialID, secret))
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestAccessTokenRevocation checks that a revoked access token introspects as inactive.
//
//conformance:covers RFC7009-2-02
func TestAccessTokenRevocation(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.revoke(revocationParams(access), nil)
	a.wantInactive(access)
}

// TestRevocationEndpointIsAbsoluteWithoutFragment checks that the revocation endpoint URL in the metadata is an absolute URL without a fragment.
//
//conformance:covers RFC7009-2-03
func TestRevocationEndpointIsAbsoluteWithoutFragment(t *testing.T) {
	raw := metadataURL(t, "revocation_endpoint")
	if u, err := url.Parse(raw); err != nil || !u.IsAbs() || u.Host == "" || strings.Contains(raw, "#") {
		t.Fatalf("got revocation_endpoint %s, want an absolute URL without a fragment", raw)
	}
}

// TestRevocationEndpointIsHTTPS checks that the revocation endpoint URL in the metadata is an https URL, also with an issuer path and a configured revocation path.
//
//conformance:covers RFC7009-2-05
func TestRevocationEndpointIsHTTPS(t *testing.T) {
	a := newConfiguredServer(t, func(c *oauth21.Config) {
		c.Issuer += "/tenant"
		c.Paths.Revocation = "/oauth/revoke"
	})
	if u, _ := a.metadata(a.url + "/tenant")["revocation_endpoint"].(string); !strings.HasPrefix(u, "https://") {
		t.Fatalf("got revocation_endpoint %q, want an https URL", u)
	}
}

// TestNoHTTPRevocationEndpointIsPublished checks that no member of the metadata names an http URL of the revocation endpoint.
//
//conformance:covers RFC7009-2-09
func TestNoHTTPRevocationEndpointIsPublished(t *testing.T) {
	a := newAuthorizationServer(t)
	for name, v := range a.metadata(a.url) {
		if s, ok := v.(string); ok && strings.HasPrefix(s, "http:") {
			t.Fatalf("got %s %s, want no http URL", name, s)
		}
	}
}

// TestRevocationSearchesBeyondHint checks that a token is revoked whatever token_type_hint names.
//
//conformance:covers RFC7009-2.1-04
func TestRevocationSearchesBeyondHint(t *testing.T) {
	for _, hint := range []string{"access_token", "refresh_token", "unknown"} {
		t.Run(hint, func(t *testing.T) {
			a := newIntrospectionServer(t)
			access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
			refresh := a.publicRefreshToken()
			for _, token := range []string{access, refresh} {
				params := revocationParams(token)
				params.Set("token_type_hint", hint)
				a.revoke(params, nil)
			}
			a.wantInactive(access)
			status, _, body := a.token(refreshParams(refresh), nil)
			a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
		})
	}
}

// TestRevokedRefreshTokenInvalidatesAccessTokens checks that revoking a refresh token invalidates the access tokens of its Grant.
//
//conformance:covers RFC7009-2.1-07
func TestRevokedRefreshTokenInvalidatesAccessTokens(t *testing.T) {
	a := newIntrospectionServer(t)
	access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.revoke(revocationParams(refresh), nil)
	a.wantInactive(access)
}

// TestHintCausesNoExtraLookups checks that a revocation request with a token_type_hint that does not match its token makes no more Store lookups than one without a hint.
func TestHintCausesNoExtraLookups(t *testing.T) {
	lookups := func(kind, hint string) int {
		a := newAuthorizationServer(t)
		access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		tokens := map[string]string{"access_token": access, "refresh_token": refresh, "unknown": "unknown"}
		params := revocationParams(tokens[kind])
		if hint != "" {
			params.Set("token_type_hint", hint)
		}
		before := len(a.recorder.keys())
		a.revoke(params, nil)
		return len(a.recorder.keys()) - before
	}
	for _, kind := range []string{"access_token", "refresh_token", "unknown"} {
		want := lookups(kind, "")
		for _, hint := range []string{"access_token", "refresh_token", "unknown"} {
			if got := lookups(kind, hint); got > want {
				t.Fatalf("got %d Store lookups for %s with hint %s, want at most %d as without a hint", got, kind, hint, want)
			}
		}
	}
}

// grantOf returns the identifier of the Grant of the access token value, as the Host Application's Store holds it.
func (a *authorizationServer) grantOf(value string) string {
	a.t.Helper()
	token, err := a.recorder.Store.Token(a.t.Context(), hashOf(value))
	if err != nil {
		a.t.Fatal(err)
	}
	return token.Grant.ID
}

// TestHostRevokesGrant checks that the Host Application can revoke a Grant it found in its Store, which deactivates its access token.
//
//conformance:covers OAUTH21D16-7.9-06
func TestHostRevokesGrant(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	other, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	if err := a.srv.RevokeGrant(t.Context(), a.grantOf(access)); err != nil {
		t.Fatal(err)
	}
	a.wantInactive(access)
	a.wantActive(other)
}

// TestHostRevokesRefreshTokens checks that revoking a Grant on a security event refuses its refresh token.
//
//conformance:covers OAUTH21D16-4.3.3-03
func TestHostRevokesRefreshTokens(t *testing.T) {
	a := newAuthorizationServer(t)
	access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	if err := a.srv.RevokeGrant(t.Context(), a.grantOf(access)); err != nil {
		t.Fatal(err)
	}
	status, _, body := a.token(refreshParams(refresh), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}
