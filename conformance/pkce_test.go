package conformance

import (
	"net/http"
	"strings"
	"testing"
)

// TestAuthorizationRequiresCodeChallenge checks that a request without a code challenge gets invalid_request.
//
//conformance:covers RFC7636-4.3-01 RFC7636-4.4.1-01 RFC7636-4.4.1-02 OAUTH21D16-4.1.1-16
func TestAuthorizationRequiresCodeChallenge(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Del("code_challenge")
	a.wantAuthorizationError(a.authorize(params), "invalid_request", "code challenge required")
}

// TestAuthorizationRejectsUnsupportedMethod checks that plain, missing and unknown methods get invalid_request.
//
//conformance:covers RFC7636-4.4.1-03 RFC7636-4.4.1-04 OAUTH21D16-4.1.1-06
func TestAuthorizationRejectsUnsupportedMethod(t *testing.T) {
	for _, method := range []string{"plain", "", "s256", "S512"} {
		t.Run(method, func(t *testing.T) {
			a := newAuthorizationServer(t)
			params := authorizeParams()
			params.Set("code_challenge", verifier)
			params.Set("code_challenge_method", method)
			if method == "" {
				params.Del("code_challenge_method")
			}
			a.wantAuthorizationError(a.authorize(params), "invalid_request", "transform algorithm not supported")
		})
	}
}

// TestCodeChallengeNotExposed checks that no redirect carries the code challenge.
//
//conformance:covers RFC7636-4.4-02
func TestCodeChallengeNotExposed(t *testing.T) {
	a := newAuthorizationServer(t)
	login := a.authorize(authorizeParams())
	callback := a.login(login, "alice")
	for _, s := range []string{login.String(), callback.String()} {
		if strings.Contains(s, challenge) {
			t.Fatalf("got redirect %s, want no code challenge in it", s)
		}
	}
}

// TestTokenRequiresCodeVerifier checks that a redemption without a code verifier gets invalid_request.
//
//conformance:covers RFC7636-4.5-01 OAUTH21D16-4.1.1-16
func TestTokenRequiresCodeVerifier(t *testing.T) {
	a := newAuthorizationServer(t)
	status, _, body := a.token(withVerifier(tokenParams(a.code(authorizeParams())), ""), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestTokenRejectsWrongCodeVerifier checks that a non-matching code verifier gets invalid_grant.
//
//conformance:covers RFC7636-4.5-02 RFC7636-4.6-02
func TestTokenRejectsWrongCodeVerifier(t *testing.T) {
	for name, v := range map[string]string{
		"other":     strings.Repeat("a", 43),
		"challenge": challenge,
		"too short": verifier[:42],
	} {
		t.Run(name, func(t *testing.T) {
			a := newAuthorizationServer(t)
			status, _, body := a.token(withVerifier(tokenParams(a.code(authorizeParams())), v), nil)
			a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
		})
	}
}

// TestCodeChallengeIsBoundToCode checks that a code redeems only with the verifier of its own request.
//
//conformance:covers RFC7636-4.4-01 RFC7636-4.5-02
func TestCodeChallengeIsBoundToCode(t *testing.T) {
	a := newAuthorizationServer(t)
	other := strings.Repeat("o", 43)
	first := a.code(authorizeParams())
	params := authorizeParams()
	params.Set("code_challenge", s256(other))
	second := a.code(params)

	status, _, body := a.token(withVerifier(tokenParams(first), other), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	if status, _, body := a.token(withVerifier(tokenParams(second), other), nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v, want 200", status, body)
	}
}
