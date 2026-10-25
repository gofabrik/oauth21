package conformance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofabrik/oauth21/bearer"
)

// validators builds each Validator the bearer middleware is tested with.
var validators = map[string]func(a *authorizationServer) bearer.Validator{
	"local":  func(a *authorizationServer) bearer.Validator { return a.local() },
	"remote": func(a *authorizationServer) bearer.Validator { return a.remote(resourceServerID, secret) },
}

// local returns the local validator of the Resource Server Client.
func (a *authorizationServer) local() bearer.Local {
	return bearer.Local{Tokens: a.recorder, ClientID: resourceServerID, Clock: a.now}
}

// remote returns the remote validator authenticating as id with clientSecret.
func (a *authorizationServer) remote(id, clientSecret string) bearer.Remote {
	return bearer.Remote{Endpoint: a.url + a.srv.Paths().Introspection, ClientID: id, ClientSecret: clientSecret, Client: a.client}
}

// forEachValidator runs test with each validator, against a new Authorization Server where the Resource Server Client may introspect.
func forEachValidator(t *testing.T, test func(a *authorizationServer, v bearer.Validator)) {
	t.Helper()
	for name, validator := range validators {
		t.Run(name, func(t *testing.T) {
			a := newIntrospectionServer(t)
			test(a, validator(a))
		})
	}
}

// resource serves the validated token of a request guarded by the bearer middleware with v that requires scopes.
func (a *authorizationServer) resource(v bearer.Validator, scopes ...string) {
	a.t.Helper()
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
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v, "read")
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		status, _, body := a.access(bearerHeader(access))
		var got bearer.Token
		if err := json.Unmarshal(body, &got); err != nil || status != http.StatusOK || got.Subject != "alice" || got.ClientID != clientID || len(got.Scopes) != 1 || got.Scopes[0] != "read" {
			a.t.Fatalf("got status %d, body %s and error %v, want the token of alice and %s with scope read", status, body, err, clientID)
		}
	})
}

// TestBearerChallengeWithoutCredentials checks that a request without Bearer credentials in the Authorization header gets 401 and a challenge without error, also when it carries an access token in the query or the body.
func TestBearerChallengeWithoutCredentials(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
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
				a.t.Fatalf("%s %s: got status %d and WWW-Authenticate %q, want 401 and %q", r.method, r.path, status, header.Get("WWW-Authenticate"), want)
			}
		}
	})
}

// TestBearerChallengeForInvalidToken checks that unknown, expired and revoked access tokens and refresh tokens get 401 and an invalid_token challenge.
func TestBearerChallengeForInvalidToken(t *testing.T) {
	want := `Bearer realm="oauth21", error="invalid_token", error_description="access token not active"`
	t.Run("unknown", func(t *testing.T) {
		forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
			a.resource(v)
			a.wantChallenge(bearerHeader("unknown"), http.StatusUnauthorized, want)
		})
	})
	t.Run("expired", func(t *testing.T) {
		forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
			a.resource(v)
			access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
			a.advance(time.Hour)
			a.wantChallenge(bearerHeader(access), http.StatusUnauthorized, want)
		})
	})
	t.Run("revoked access token", func(t *testing.T) {
		forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
			a.resource(v)
			access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
			a.revoke(revocationParams(access), nil)
			a.wantChallenge(bearerHeader(access), http.StatusUnauthorized, want)
		})
	})
	t.Run("access token of a revoked Grant", func(t *testing.T) {
		forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
			a.resource(v)
			access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
			a.revoke(revocationParams(refresh), nil)
			a.wantChallenge(bearerHeader(access), http.StatusUnauthorized, want)
		})
	})
	t.Run("refresh token", func(t *testing.T) {
		forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
			a.resource(v)
			a.wantChallenge(bearerHeader(a.publicRefreshToken()), http.StatusUnauthorized, want)
		})
	})
}

// TestBearerChallengeForMalformedRequest checks that malformed Bearer credentials and a repeated Authorization header get 400 and an invalid_request challenge.
func TestBearerChallengeForMalformedRequest(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		want := `Bearer realm="oauth21", error="invalid_request", error_description="malformed Bearer credentials"`
		for _, credentials := range []string{"Bearer", "Bearer a b", "Bearer =abc"} {
			a.wantChallenge(http.Header{"Authorization": {credentials}}, http.StatusBadRequest, want)
		}
		repeated := http.Header{"Authorization": {"Bearer " + access, "Bearer " + access}}
		a.wantChallenge(repeated, http.StatusBadRequest, `Bearer realm="oauth21", error="invalid_request", error_description="repeated Authorization header"`)
	})
}

// TestBearerChallengeForInsufficientScope checks that an access token without a required scope gets 403 and an insufficient_scope challenge with the required scopes, and that the scheme is case-insensitive.
func TestBearerChallengeForInsufficientScope(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v, "read", "write")
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.wantChallenge(http.Header{"Authorization": {"bEaReR " + access}}, http.StatusForbidden, `Bearer realm="oauth21", scope="read write", error="insufficient_scope", error_description="access token lacks a required scope"`)
		a.wantChallenge(nil, http.StatusUnauthorized, `Bearer realm="oauth21", scope="read write"`)
		params := authorizeParams()
		params.Set("scope", "read write")
		access, _ = a.tokens(tokenParams(a.code(params)), nil)
		if status, _, body := a.access(http.Header{"Authorization": {"bEaReR " + access}}); status != http.StatusOK {
			a.t.Fatalf("got status %d and body %s with both scopes, want 200", status, body)
		}
	})
}

// TestBearerRemoteValidationFailureIsServerError checks that the remote validator gets 500 without a challenge when introspection fails: its credentials are invalid, its Client may not introspect, or the endpoint is missing, unreachable or redirects, even with an HTTP client that follows redirects.
func TestBearerRemoteValidationFailureIsServerError(t *testing.T) {
	for name, v := range map[string]func(a *authorizationServer) bearer.Remote{
		"invalid credentials":       func(a *authorizationServer) bearer.Remote { return a.remote(resourceServerID, "wrong") },
		"Client without Introspect": func(a *authorizationServer) bearer.Remote { return a.remote(confidentialID, secret) },
		"missing endpoint": func(a *authorizationServer) bearer.Remote {
			r := a.remote(resourceServerID, secret)
			r.Endpoint = a.url + "/missing"
			return r
		},
		"unreachable endpoint": func(a *authorizationServer) bearer.Remote {
			closed := httptest.NewServer(http.NotFoundHandler())
			closed.Close()
			r := a.remote(resourceServerID, secret)
			r.Endpoint = closed.URL + a.srv.Paths().Introspection
			return r
		},
		"redirecting endpoint": func(a *authorizationServer) bearer.Remote {
			a.mux.Handle("/moved", http.RedirectHandler(a.srv.Paths().Introspection, http.StatusTemporaryRedirect))
			client := *a.client
			client.CheckRedirect = nil
			r := a.remote(resourceServerID, secret)
			r.Endpoint, r.Client = a.url+"/moved", &client
			return r
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := newIntrospectionServer(t)
			a.resource(v(a))
			access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
			if status, header, _ := a.access(bearerHeader(access)); status != http.StatusInternalServerError || header.Get("WWW-Authenticate") != "" {
				t.Fatalf("got status %d and WWW-Authenticate %q, want 500 without a challenge", status, header.Get("WWW-Authenticate"))
			}
		})
	}
}
