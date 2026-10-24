package conformance

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gofabrik/oauth21/bearer"
)

// resource serves the validated token of a request guarded by the bearer middleware that requires scopes.
func (a *authorizationServer) resource(scopes ...string) {
	a.t.Helper()
	v := bearer.Local{Tokens: a.recorder, Clock: a.now}
	a.mux.Handle("/resource", bearer.Middleware(v, scopes...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := bearer.FromContext(r.Context())
		_ = json.NewEncoder(w).Encode(token)
	})))
}

// access sends a request with header to the protected resource and returns the status, headers and body of the response.
func (a *authorizationServer) access(header http.Header) (int, http.Header, []byte) {
	a.t.Helper()
	return a.send(http.MethodGet, "/resource", "", header)
}

// bearerHeader returns an Authorization header carrying token.
func bearerHeader(token string) http.Header {
	return http.Header{"Authorization": {"Bearer " + token}}
}

// wantChallenge checks that a request with header to the protected resource gets wantStatus and the Bearer challenge want.
func (a *authorizationServer) wantChallenge(header http.Header, wantStatus int, want string) {
	a.t.Helper()
	status, respHeader, _ := a.access(header)
	if status != wantStatus || respHeader.Get("WWW-Authenticate") != want {
		a.t.Fatalf("got status %d and WWW-Authenticate %q, want %d and %q", status, respHeader.Get("WWW-Authenticate"), wantStatus, want)
	}
}

// TestBearerTokenReachesHandler checks that a valid access token in the Authorization header gives the handler its subject, Client and scopes.
func TestBearerTokenReachesHandler(t *testing.T) {
	a := newAuthorizationServer(t)
	a.resource("read")
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	status, _, body := a.access(bearerHeader(access))
	var got bearer.Token
	if err := json.Unmarshal(body, &got); err != nil || status != http.StatusOK || got.Subject != "alice" || got.ClientID != clientID || len(got.Scopes) != 1 || got.Scopes[0] != "read" {
		t.Fatalf("got status %d, body %s and error %v, want the token of alice and %s with scope read", status, body, err, clientID)
	}
}

// TestBearerChallengeWithoutCredentials checks that a request without Bearer credentials in the Authorization header gets 401 and a challenge without error, also when it carries an access token in the query or the body.
func TestBearerChallengeWithoutCredentials(t *testing.T) {
	a := newAuthorizationServer(t)
	a.resource()
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	want := `Bearer realm="oauth21"`
	a.wantChallenge(nil, http.StatusUnauthorized, want)
	a.wantChallenge(basic(clientID, access), http.StatusUnauthorized, want)
	for _, r := range []struct{ method, path, form string }{
		{http.MethodGet, "/resource?access_token=" + access, ""},
		{http.MethodPost, "/resource", "access_token=" + access},
	} {
		status, header, _ := a.send(r.method, r.path, r.form, nil)
		if status != http.StatusUnauthorized || header.Get("WWW-Authenticate") != want {
			t.Fatalf("%s %s: got status %d and WWW-Authenticate %q, want 401 and %q", r.method, r.path, status, header.Get("WWW-Authenticate"), want)
		}
	}
}

// TestBearerChallengeForInvalidToken checks that unknown, expired and revoked access tokens and refresh tokens get 401 and an invalid_token challenge.
func TestBearerChallengeForInvalidToken(t *testing.T) {
	want := `Bearer realm="oauth21", error="invalid_token", error_description="access token not active"`
	t.Run("unknown", func(t *testing.T) {
		a := newAuthorizationServer(t)
		a.resource()
		a.wantChallenge(bearerHeader("unknown"), http.StatusUnauthorized, want)
	})
	t.Run("expired", func(t *testing.T) {
		a := newAuthorizationServer(t)
		a.resource()
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.advance(time.Hour)
		a.wantChallenge(bearerHeader(access), http.StatusUnauthorized, want)
	})
	t.Run("revoked access token", func(t *testing.T) {
		a := newAuthorizationServer(t)
		a.resource()
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.revoke(revocationParams(access), nil)
		a.wantChallenge(bearerHeader(access), http.StatusUnauthorized, want)
	})
	t.Run("access token of a revoked Grant", func(t *testing.T) {
		a := newAuthorizationServer(t)
		a.resource()
		access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.revoke(revocationParams(refresh), nil)
		a.wantChallenge(bearerHeader(access), http.StatusUnauthorized, want)
	})
	t.Run("refresh token", func(t *testing.T) {
		a := newAuthorizationServer(t)
		a.resource()
		a.wantChallenge(bearerHeader(a.publicRefreshToken()), http.StatusUnauthorized, want)
	})
}

// TestBearerChallengeForMalformedRequest checks that malformed Bearer credentials and a repeated Authorization header get 400 and an invalid_request challenge.
func TestBearerChallengeForMalformedRequest(t *testing.T) {
	a := newAuthorizationServer(t)
	a.resource()
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	want := `Bearer realm="oauth21", error="invalid_request", error_description="malformed Bearer credentials"`
	for _, credentials := range []string{"Bearer", "Bearer a b", "Bearer =abc"} {
		a.wantChallenge(http.Header{"Authorization": {credentials}}, http.StatusBadRequest, want)
	}
	repeated := http.Header{"Authorization": {"Bearer " + access, "Bearer " + access}}
	a.wantChallenge(repeated, http.StatusBadRequest, `Bearer realm="oauth21", error="invalid_request", error_description="repeated Authorization header"`)
}

// TestBearerChallengeForInsufficientScope checks that an access token without a required scope gets 403 and an insufficient_scope challenge with the required scopes, and that the scheme is case-insensitive.
func TestBearerChallengeForInsufficientScope(t *testing.T) {
	a := newAuthorizationServer(t)
	a.resource("read", "write")
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.wantChallenge(http.Header{"Authorization": {"bEaReR " + access}}, http.StatusForbidden, `Bearer realm="oauth21", scope="read write", error="insufficient_scope", error_description="access token lacks a required scope"`)
	a.wantChallenge(nil, http.StatusUnauthorized, `Bearer realm="oauth21", scope="read write"`)
	params := authorizeParams()
	params.Set("scope", "read write")
	access, _ = a.tokens(tokenParams(a.code(params)), nil)
	if status, _, body := a.access(http.Header{"Authorization": {"bEaReR " + access}}); status != http.StatusOK {
		t.Fatalf("got status %d and body %s with both scopes, want 200", status, body)
	}
}
