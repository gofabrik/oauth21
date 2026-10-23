package conformance

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofabrik/oauth21"
)

// TestAuthorizationCodeFlow checks that a public Client redeems a code with its verifier for an access token.
//
//conformance:covers RFC7636-4.2-02 RFC7636-4.4-01 RFC7636-4.5-02 RFC7636-4.6-01
func TestAuthorizationCodeFlow(t *testing.T) {
	a := newAuthorizationServer(t)
	u := a.login(a.authorize(authorizeParams()), "alice")

	q := u.Query()
	if got := endpoint(u); got != redirectURI {
		t.Fatalf("got redirect to %s, want %s", got, redirectURI)
	}
	if q.Get("code") == "" || q.Get("state") != state || q.Get("iss") != a.url {
		t.Fatalf("got redirect %s, want code, state %q and iss %q", u, state, a.url)
	}

	status, _, body := a.token(tokenParams(q.Get("code")), nil)
	if status != http.StatusOK {
		t.Fatalf("got status %d and body %v, want 200", status, body)
	}
	if tok, _ := body["access_token"].(string); tok == "" || body["token_type"] != "Bearer" {
		t.Fatalf("got body %v, want a Bearer access token", body)
	}
	if expires, _ := body["expires_in"].(float64); expires <= 0 {
		t.Fatalf("got expires_in %v, want a positive lifetime", body["expires_in"])
	}
}

// TestCodeExpires checks that a code cannot be redeemed after its lifetime.
func TestCodeExpires(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	a.advance(10 * time.Minute)
	status, _, body := a.token(params, nil)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestTokenResponseCarriesGrantedScope checks that the token response names the granted scopes.
func TestTokenResponseCarriesGrantedScope(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("scope", "read write")
	req := a.pending(a.authorize(params))
	u := a.complete(req.ID, oauth21.Completion{Subject: "alice", Scopes: []string{"read"}})
	status, _, body := a.token(tokenParams(u.Query().Get("code")), nil)
	if status != http.StatusOK || body["scope"] != "read" {
		t.Fatalf("got status %d and body %v, want scope read", status, body)
	}
}

// TestRejectedCompletionKeepsRequest checks that a Completion without a subject or granted scopes is rejected and leaves the request pending.
func TestRejectedCompletionKeepsRequest(t *testing.T) {
	for name, c := range map[string]oauth21.Completion{"no subject": {Scopes: []string{"read"}}, "no scopes": {Subject: "alice"}} {
		t.Run(name, func(t *testing.T) {
			a := newAuthorizationServer(t)
			params := authorizeParams()
			params.Set("scope", "read")
			req := a.pending(a.authorize(params))
			if _, err := a.srv.Complete(t.Context(), req.ID, c); !errors.Is(err, oauth21.ErrInvalidCompletion) {
				t.Fatalf("got error %v, want ErrInvalidCompletion", err)
			}
			if u := a.complete(req.ID, oauth21.Completion{Subject: "alice", Scopes: []string{"read"}}); u.Query().Get("code") == "" {
				t.Fatalf("got redirect %s, want a code", u)
			}
		})
	}
}

// TestCodeIsSingleUse checks that a second redemption of a code fails.
func TestCodeIsSingleUse(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	if status, _, body := a.token(params, nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v, want 200", status, body)
	}
	status, _, body := a.token(params, nil)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestPublicClientCredentialsAreRejected checks that a public Client sending credentials gets invalid_client.
func TestPublicClientCredentialsAreRejected(t *testing.T) {
	for _, scheme := range []string{"Basic", "Bearer"} {
		t.Run(scheme, func(t *testing.T) {
			a := newAuthorizationServer(t)
			header := http.Header{}
			header.Set("Authorization", scheme+" "+base64.StdEncoding.EncodeToString([]byte("other:wrong")))
			status, respHeader, body := a.token(tokenParams(a.code(authorizeParams())), header)
			a.wantTokenError(status, body, http.StatusUnauthorized, "invalid_client")
			if got, _, _ := strings.Cut(respHeader.Get("WWW-Authenticate"), " "); got != scheme {
				t.Fatalf("got WWW-Authenticate %q, want the %s scheme", respHeader.Get("WWW-Authenticate"), scheme)
			}
		})
	}
	t.Run("client_secret", func(t *testing.T) {
		a := newAuthorizationServer(t)
		params := tokenParams(a.code(authorizeParams()))
		params.Set("client_secret", "wrong")
		status, _, body := a.token(params, nil)
		a.wantTokenError(status, body, http.StatusBadRequest, "invalid_client")
	})
}

// TestFailedRedemptionKeepsCode checks that a wrong code verifier does not use up the code.
func TestFailedRedemptionKeepsCode(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	status, _, body := a.token(withVerifier(params, strings.Repeat("w", 43)), nil)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
	if status, _, body := a.token(params, nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v after a failed attempt, want 200", status, body)
	}
}
