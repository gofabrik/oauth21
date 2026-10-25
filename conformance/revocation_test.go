package conformance

import (
	"net/http"
	"net/url"
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

// TestRevocationRequestErrors checks that a revocation request without a token or not sent with POST fails with invalid_request.
func TestRevocationRequestErrors(t *testing.T) {
	a := newAuthorizationServer(t)
	a.wantRevocationError(url.Values{"client_id": {clientID}}, nil, http.StatusBadRequest, "invalid_request")
	status, _, body := a.sendJSON(http.MethodGet, "/revoke?"+revocationParams("unknown").Encode(), "", nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}
