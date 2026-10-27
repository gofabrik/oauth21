package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofabrik/oauth21/store"
)

// TestAuthorizationRequiresCodeChallenge checks that a request without a code challenge gets an error instead of a code.
//
//conformance:covers RFC7636-4.3-01
func TestAuthorizationRequiresCodeChallenge(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Del("code_challenge")
	if q := a.errorRedirect(params).Query(); q.Has("code") || !q.Has("error") {
		t.Fatalf("got redirect query %v, want an error and no code", q)
	}
}

// TestMissingCodeChallengeGetsInvalidRequest checks that a request without a code challenge gets invalid_request.
//
//conformance:covers RFC7636-4.4.1-01
func TestMissingCodeChallengeGetsInvalidRequest(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Del("code_challenge")
	a.wantAuthorizationError(a.errorRedirect(params), "invalid_request", "")
}

// TestMissingCodeChallengeIsExplained checks that the error_description says a code challenge is required.
//
//conformance:covers RFC7636-4.4.1-02
func TestMissingCodeChallengeIsExplained(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Del("code_challenge")
	a.wantAuthorizationError(a.errorRedirect(params), "invalid_request", "code challenge required")
}

// TestServerEnforcesPKCE checks that neither the code challenge nor the code verifier can be left out.
//
//conformance:covers OAUTH21D16-4.1.1-16
func TestServerEnforcesPKCE(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Del("code_challenge")
	a.wantAuthorizationError(a.errorRedirect(params), "invalid_request", "")
	a.wantVerifierRequired(tokenParams(a.code(authorizeParams())), nil)
}

// TestAuthorizationRejectsUnsupportedMethod checks that plain, missing and unknown methods get invalid_request.
//
//conformance:covers RFC7636-4.4.1-03
func TestAuthorizationRejectsUnsupportedMethod(t *testing.T) {
	wantUnsupportedMethodRejected(t, "")
}

// TestUnsupportedTransformIsExplained checks that the error_description of plain, missing and unknown methods says the transform algorithm is not supported.
//
//conformance:covers RFC7636-4.4.1-04
func TestUnsupportedTransformIsExplained(t *testing.T) {
	wantUnsupportedMethodRejected(t, "transform algorithm not supported")
}

// wantUnsupportedMethodRejected checks that plain, missing and unknown methods get invalid_request with description in the error_description.
func wantUnsupportedMethodRejected(t *testing.T, description string) {
	t.Helper()
	for _, method := range []string{"plain", "", "s256", "S512"} {
		t.Run(method, func(t *testing.T) {
			a := newAuthorizationServer(t)
			params := authorizeParams()
			params.Set("code_challenge", verifier)
			params.Set("code_challenge_method", method)
			if method == "" {
				params.Del("code_challenge_method")
			}
			a.wantAuthorizationError(a.errorRedirect(params), "invalid_request", description)
		})
	}
}

// TestAuthorizationRequiresCodeChallengeMethod checks that a request without a code_challenge_method gets invalid_request.
//
//conformance:covers OAUTH21D16-4.1.1-06
func TestAuthorizationRequiresCodeChallengeMethod(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Del("code_challenge_method")
	a.wantAuthorizationError(a.errorRedirect(params), "invalid_request", "")
}

// TestCodeChallengeNotExposed checks that no redirect carries the code challenge: with the same randomness source, requests with different code challenges get the same login and callback redirects.
//
//conformance:covers RFC7636-4.4-02
func TestCodeChallengeNotExposed(t *testing.T) {
	logins, callbacks := redirectsPerChallenge(t, verifier, strings.Repeat("o", 43))
	if logins[0] != logins[1] {
		t.Fatalf("got login redirects %q for two code challenges, want the same redirect", logins)
	}
	if callbacks[0] != callbacks[1] {
		t.Fatalf("got callback redirects %q for two code challenges, want the same redirect", callbacks)
	}
}

// redirectsPerChallenge returns the login and callback redirects of a request with the code challenge of each of verifiers, each on its own server with the same randomness source and its URL replaced by "server".
func redirectsPerChallenge(t *testing.T, verifiers ...string) (logins, callbacks []string) {
	t.Helper()
	for _, v := range verifiers {
		a := newSeededServer(t, &seededRandom{seed: 1})
		params := authorizeParams()
		params.Set("code_challenge", s256(v))
		login := a.authorize(params)
		callback := a.login(login, "alice")
		server := strings.NewReplacer(a.url, "server", url.QueryEscape(a.url), "server")
		logins = append(logins, server.Replace(login.String()))
		callbacks = append(callbacks, server.Replace(callback.String()))
	}
	return logins, callbacks
}

// TestTokenRequiresCodeVerifier checks that a redemption without a code verifier gets invalid_request.
//
//conformance:covers RFC7636-4.5-01
func TestTokenRequiresCodeVerifier(t *testing.T) {
	a := newAuthorizationServer(t)
	a.wantVerifierRequired(tokenParams(a.code(authorizeParams())), nil)
}

// wantVerifierRequired checks that the token request params with header gets invalid_request without its code_verifier.
func (a *authorizationServer) wantVerifierRequired(params url.Values, header http.Header) {
	a.t.Helper()
	status, _, body := a.token(withVerifier(params, ""), header)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestTokenRejectsWrongCodeVerifier checks that a non-matching code verifier gets invalid_grant.
//
//conformance:covers RFC7636-4.6-02
func TestTokenRejectsWrongCodeVerifier(t *testing.T) {
	for name, v := range map[string]string{
		"other":          strings.Repeat("a", 43),
		"too short":      verifier[:42],
		"code challenge": challenge,
	} {
		t.Run(name, func(t *testing.T) {
			a := newAuthorizationServer(t)
			status, _, body := a.token(withVerifier(tokenParams(a.code(authorizeParams())), v), nil)
			a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
		})
	}
}

// TestTokenVerifiesWithS256 checks that the code verifier is compared through S256, not as the code challenge itself.
//
//conformance:covers RFC7636-4.5-02
func TestTokenVerifiesWithS256(t *testing.T) {
	a := newAuthorizationServer(t)
	status, _, body := a.token(withVerifier(tokenParams(a.code(authorizeParams())), challenge), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	if status, _, body := a.token(tokenParams(a.code(authorizeParams())), nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v, want 200", status, body)
	}
}

// TestCodeChallengeIsBoundToCode checks that a code redeems only with the verifier of its own request.
//
//conformance:covers RFC7636-4.4-01
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

// TestServerSupportsPKCE checks that a code requested with a code challenge redeems with its code verifier.
//
//conformance:covers OAUTH21D16-4.1.1-14
func TestServerSupportsPKCE(t *testing.T) {
	a := newAuthorizationServer(t)
	if status, _, body := a.token(tokenParams(a.code(authorizeParams())), nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v, want 200", status, body)
	}
}

// TestServerSupportsS256 checks that a code requested with the S256 code challenge of RFC 7636 Appendix B redeems with its code verifier.
//
//conformance:covers RFC7636-4.2-02
func TestServerSupportsS256(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	params.Set("code_challenge_method", "S256")
	if status, _, body := a.token(withVerifier(tokenParams(a.code(params)), "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v, want 200", status, body)
	}
}

// TestEmptyCodeChallengeIsMissing checks that a code_challenge without a value gets invalid_request.
//
//conformance:covers OAUTH21D16-4.1.1-05
func TestEmptyCodeChallengeIsMissing(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("code_challenge", "")
	a.wantAuthorizationError(a.errorRedirect(params), "invalid_request", "code challenge required")
}

// TestPublicClientRequiresCodeChallenge checks that a public Client's request without a code challenge is rejected.
//
//conformance:covers OAUTH21D16-4.1.2.1-05
func TestPublicClientRequiresCodeChallenge(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Del("code_challenge")
	params.Del("code_challenge_method")
	a.wantAuthorizationError(a.errorRedirect(params), "invalid_request", "code challenge required")
}

// TestConfidentialClientRequiresCodeChallenge checks that a confidential Client's request without a code challenge is rejected.
//
//conformance:covers OAUTH21D16-4.1.2.1-06
func TestConfidentialClientRequiresCodeChallenge(t *testing.T) {
	a := newConfidentialServer(t)
	params := authorizeParams()
	params.Set("client_id", confidentialID)
	params.Del("code_challenge")
	a.wantAuthorizationError(a.errorRedirect(params), "invalid_request", "code challenge required")
}

// TestConfidentialClientRequiresCodeVerifier checks that an authenticated confidential Client cannot redeem a code without its code verifier.
//
//conformance:covers OAUTH21D16-7.5.1.1-02
func TestConfidentialClientRequiresCodeVerifier(t *testing.T) {
	a := newConfidentialServer(t)
	a.wantVerifierRequired(a.confidentialCode(), basic(confidentialID, secret))
}

// TestPublicClientRequiresCodeVerifier checks that a public Client cannot redeem a code requested with a code challenge without its code verifier, also when the code was requested with a scope.
//
//conformance:covers OAUTH21D16-4.1.3-02
func TestPublicClientRequiresCodeVerifier(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("scope", "read write")
	a.wantVerifierRequired(tokenParams(a.code(params)), nil)
}

// TestEmptyCodeVerifierIsMissing checks that a code_verifier without a value counts as missing for a code with a code challenge.
//
//conformance:covers OAUTH21D16-4.1.3-10
func TestEmptyCodeVerifierIsMissing(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	params.Set("code_verifier", "")
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestCodeVerifierIsTransformed checks that the code verifier is compared after the S256 transformation, so presenting the code challenge itself fails and the code verifier redeems.
//
//conformance:covers OAUTH21D16-4.1.3-11
func TestCodeVerifierIsTransformed(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	status, _, body := a.token(withVerifier(params, challenge), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	if status, _, body := a.token(params, nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v, want 200", status, body)
	}
}

// TestCodeChallengeIsAssociatedWithCode checks that two codes with different code challenges do not redeem with each other's verifier but redeem with their own.
//
//conformance:covers OAUTH21D16-4.1.2-07
func TestCodeChallengeIsAssociatedWithCode(t *testing.T) {
	a := newAuthorizationServer(t)
	other := strings.Repeat("o", 43)
	params := authorizeParams()
	params.Set("code_challenge", s256(other))
	codes := map[string]string{a.code(authorizeParams()): verifier, a.code(params): other}
	for code, own := range codes {
		for _, v := range codes {
			if v != own {
				status, _, body := a.token(withVerifier(tokenParams(code), v), nil)
				a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
			}
		}
		if status, _, body := a.token(withVerifier(tokenParams(code), own), nil); status != http.StatusOK {
			t.Fatalf("got status %d and body %v with the code's own verifier, want 200", status, body)
		}
	}
}

// TestUnsupportedMethodIsInvalidRequest checks that an unknown code challenge method gets invalid_request also with a valid S256 code challenge.
//
//conformance:covers OAUTH21D16-4.1.2.1-07
func TestUnsupportedMethodIsInvalidRequest(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("code_challenge_method", "S512")
	if q := a.errorRedirect(params).Query(); q.Get("error") != "invalid_request" {
		t.Fatalf("got %v, want error invalid_request", q)
	}
}

// TestUnsupportedMethodIsExplained checks that the error_description of an unsupported code challenge method names the cause.
//
//conformance:covers OAUTH21D16-4.1.2.1-08
func TestUnsupportedMethodIsExplained(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Set("code_challenge_method", "S512")
	if d := a.errorRedirect(params).Query().Get("error_description"); !strings.Contains(d, "transform algorithm not supported") {
		t.Fatalf("got error_description %q, want it to name the unsupported transform algorithm", d)
	}
}

// TestCodeDoesNotCarryCodeChallenge checks that the authorization response carries only code, state and iss, and that none of them depends on the code challenge: with the same randomness source, requests with different code challenges get the same authorization response.
//
//conformance:covers OAUTH21D16-4.1.2-08
func TestCodeDoesNotCarryCodeChallenge(t *testing.T) {
	_, callbacks := redirectsPerChallenge(t, verifier, strings.Repeat("o", 43))
	for _, callback := range callbacks {
		u, err := url.Parse(callback)
		if err != nil {
			t.Fatal(err)
		}
		for name := range u.Query() {
			if name != "code" && name != "state" && name != "iss" {
				t.Fatalf("got parameter %q in %s, want only code, state and iss", name, callback)
			}
		}
	}
	if callbacks[0] != callbacks[1] {
		t.Fatalf("got authorization responses %q for two code challenges, want the same response", callbacks)
	}
}

// createCodeWithoutChallenge stores a code of the public Client without a code challenge, which the server never issues, and returns its value.
func (a *authorizationServer) createCodeWithoutChallenge() string {
	a.t.Helper()
	value, hash := randomWithHash(a.t)
	c := store.Code{Hash: hash, Grant: aliceGrant("grant-without-challenge"), RedirectURI: redirectURI, ExpiresAt: a.now().Add(time.Minute), RetainUntil: a.now().Add(time.Hour)}
	if err := a.recorder.CreateCode(a.t.Context(), c); err != nil {
		a.t.Fatal(err)
	}
	return value
}

// TestCodeWithoutChallengeIsRejected checks that a code associated with no code challenge redeems neither without nor with a code verifier.
//
//conformance:covers OAUTH21D16-4.1.3-12
func TestCodeWithoutChallengeIsRejected(t *testing.T) {
	for name, v := range map[string]string{"no verifier": "", "verifier": verifier} {
		t.Run(name, func(t *testing.T) {
			a := newAuthorizationServer(t)
			params := withVerifier(tokenParams(a.createCodeWithoutChallenge()), v)
			if status, _, body := a.token(params, nil); status != http.StatusBadRequest || body["access_token"] != nil {
				t.Fatalf("got status %d and body %v, want 400 without an access token", status, body)
			}
		})
	}
}

// TestAuthorizationServerSupportsPKCE checks that a code requested with an S256 code challenge redeems with its code verifier only.
//
//conformance:covers RFC9700-2.1.1-07
func TestAuthorizationServerSupportsPKCE(t *testing.T) {
	a := newAuthorizationServer(t)
	if status, _, body := a.token(withVerifier(tokenParams(a.code(authorizeParams())), strings.Repeat("b", 43)), nil); status == http.StatusOK {
		t.Fatalf("got status 200 and body %v for another code verifier, want an error", body)
	}
	if status, _, body := a.token(tokenParams(a.code(authorizeParams())), nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v, want 200", status, body)
	}
}

// TestCodeChallengeEnforcesCodeVerifier checks that a code requested with a code challenge redeems neither without a code verifier nor with a wrong one.
//
//conformance:covers RFC9700-2.1.1-08
func TestCodeChallengeEnforcesCodeVerifier(t *testing.T) {
	for name, v := range map[string]string{"missing": "", "other": strings.Repeat("a", 43), "challenge": challenge, "one character off": verifier[:42] + "j"} {
		t.Run(name, func(t *testing.T) {
			a := newAuthorizationServer(t)
			if status, _, body := a.token(withVerifier(tokenParams(a.code(authorizeParams())), v), nil); status != http.StatusBadRequest || body["access_token"] != nil {
				t.Fatalf("got status %d and body %v, want 400 without an access token", status, body)
			}
		})
	}
}

// TestCodeVerifierIsAcceptedOnlyWithCodeChallenge checks that a code verifier redeems a code requested with its code challenge, but not a code associated with no code challenge.
//
//conformance:covers RFC9700-2.1.1-09
func TestCodeVerifierIsAcceptedOnlyWithCodeChallenge(t *testing.T) {
	a := newAuthorizationServer(t)
	if status, _, body := a.token(tokenParams(a.createCodeWithoutChallenge()), nil); status == http.StatusOK || body["access_token"] != nil {
		t.Fatalf("got status %d and body %v without a code challenge, want an error", status, body)
	}
	if status, _, body := a.token(tokenParams(a.code(authorizeParams())), nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v with a code challenge, want 200", status, body)
	}
}

// TestPKCEDowngradeIsMitigated checks the PKCE downgrade attack: an authorization request stripped of its code challenge gets no code, and a code without a code challenge does not redeem with an attacker's code verifier.
//
//conformance:covers RFC9700-4.8.2-01
func TestPKCEDowngradeIsMitigated(t *testing.T) {
	a := newAuthorizationServer(t)
	params := authorizeParams()
	params.Del("code_challenge")
	params.Del("code_challenge_method")
	if u := a.errorRedirect(params); endpoint(u) != redirectURI || !u.Query().Has("error") {
		t.Fatalf("got redirect %s, want an error at the Client", u)
	}
	attacker := strings.Repeat("x", 43)
	if status, _, body := a.token(withVerifier(tokenParams(a.createCodeWithoutChallenge()), attacker), nil); status == http.StatusOK || body["access_token"] != nil {
		t.Fatalf("got status %d and body %v, want an error", status, body)
	}
}

// TestCodeVerifierWithoutCodeChallengeIsRejected checks that a token request with a code verifier is rejected for a code associated with no code challenge, whatever the verifier.
//
//conformance:covers RFC9700-4.8.2-03
func TestCodeVerifierWithoutCodeChallengeIsRejected(t *testing.T) {
	for name, v := range map[string]string{"verifier": verifier, "other": strings.Repeat("a", 128), "short": strings.Repeat("a", 43)} {
		t.Run(name, func(t *testing.T) {
			a := newAuthorizationServer(t)
			status, _, body := a.token(withVerifier(tokenParams(a.createCodeWithoutChallenge()), v), nil)
			if status != http.StatusBadRequest || body["error"] == nil || body["access_token"] != nil {
				t.Fatalf("got status %d and body %v, want a 400 error without an access token", status, body)
			}
		})
	}
}
