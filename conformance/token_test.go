package conformance

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/store"
)

// redeem redeems a code of the public Client and returns the decoded JSON body of the token response, which must succeed.
func (a *authorizationServer) redeem() map[string]any {
	a.t.Helper()
	status, _, body := a.token(tokenParams(a.code(authorizeParams())), nil)
	if status != http.StatusOK {
		a.t.Fatalf("got status %d and body %v, want 200", status, body)
	}
	return body
}

// TestTokenResponseCarriesAccessToken checks that a successful token response carries an access_token.
//
//conformance:covers OAUTH21D16-3.2.3-01
func TestTokenResponseCarriesAccessToken(t *testing.T) {
	a := newAuthorizationServer(t)
	if tok, _ := a.redeem()["access_token"].(string); tok == "" {
		t.Fatal("got no access_token")
	}
}

// TestTokenResponseCarriesTokenType checks that a successful token response names the Bearer token_type.
//
//conformance:covers OAUTH21D16-3.2.3-02
func TestTokenResponseCarriesTokenType(t *testing.T) {
	a := newAuthorizationServer(t)
	if body := a.redeem(); body["token_type"] != "Bearer" {
		t.Fatalf("got token_type %v, want Bearer", body["token_type"])
	}
}

// TestTokenResponseCarriesExpiresIn checks that a successful token response gives the access token lifetime in expires_in.
//
//conformance:covers OAUTH21D16-3.2.3-03
func TestTokenResponseCarriesExpiresIn(t *testing.T) {
	a := newAuthorizationServer(t)
	if body := a.redeem(); body["expires_in"] != float64(3600) {
		t.Fatalf("got expires_in %v, want 3600", body["expires_in"])
	}
}

// TestTokenResponseOmitsAbsentMembers checks that a token response without a refresh token leaves the member out instead of sending null.
//
//conformance:covers OAUTH21D16-C.3-01
func TestTokenResponseOmitsAbsentMembers(t *testing.T) {
	a := newServiceServer(t)
	_, _, body := a.token(clientCredentialsParams(""), basic(serviceID, secret))
	if _, ok := body["refresh_token"]; ok {
		t.Fatalf("got body %v, want no refresh_token member", body)
	}
	for name, v := range body {
		if v == nil {
			t.Fatalf("got null %s in %v, want absent members left out", name, body)
		}
	}
}

// TestTokenResponseMembersAppearOnce checks that successful and failed token responses carry each member once.
//
//conformance:covers OAUTH21D16-3.2-07
func TestTokenResponseMembersAppearOnce(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	for range 2 {
		_, _, raw := a.send(http.MethodPost, "/token", params.Encode(), nil)
		if _, err := members(raw); err != nil {
			t.Fatalf("got body %s: %v", raw, err)
		}
	}
}

// tokenErrors returns the bodies of token requests failing for an unknown code, a missing code verifier, an unsupported grant type, an unknown scope and a wrong Client secret, some with characters outside those error values may have.
func (a *authorizationServer) tokenErrors() []map[string]any {
	a.t.Helper()
	grant := tokenParams("")
	grant.Set("grant_type", "päss\"word\\")
	var bodies []map[string]any
	for _, r := range []struct {
		params url.Values
		header http.Header
	}{
		{tokenParams("cöde\"\\"), nil},
		{withVerifier(tokenParams(a.code(authorizeParams())), ""), nil},
		{grant, nil},
		{clientCredentialsParams("read ünknown"), basic(confidentialID, secret)},
		{a.confidentialCode(), basic(confidentialID, "wrong")},
	} {
		status, _, body := a.token(r.params, r.header)
		if status < 400 {
			a.t.Fatalf("got status %d and body %v, want an error", status, body)
		}
		bodies = append(bodies, body)
	}
	return bodies
}

// TestTokenErrorCarriesError checks that every token error response carries error.
//
//conformance:covers OAUTH21D16-3.2.4-01
func TestTokenErrorCarriesError(t *testing.T) {
	a := newConfidentialServer(t)
	for _, body := range a.tokenErrors() {
		if code, _ := body["error"].(string); code == "" {
			t.Fatalf("got body %v, want error", body)
		}
	}
}

// TestTokenErrorCodeCharacters checks that token error codes use only the allowed characters.
//
//conformance:covers OAUTH21D16-3.2.4-04
func TestTokenErrorCodeCharacters(t *testing.T) {
	a := newConfidentialServer(t)
	for _, body := range a.tokenErrors() {
		if code, _ := body["error"].(string); !errorChars(code) {
			t.Fatalf("got body %v, want an error code of the allowed characters", body)
		}
	}
}

// TestTokenErrorDescriptionCharacters checks that token error descriptions use only the allowed characters, also for requests with other characters.
//
//conformance:covers OAUTH21D16-3.2.4-06
func TestTokenErrorDescriptionCharacters(t *testing.T) {
	a := newConfidentialServer(t)
	for _, body := range a.tokenErrors() {
		if d, _ := body["error_description"].(string); d == "" || !errorChars(d) {
			t.Fatalf("got body %v, want an error_description of the allowed characters", body)
		}
	}
}

// TestUnknownCodeIsRejected checks that a token request with a code the server did not issue gets invalid_grant.
//
//conformance:covers OAUTH21D16-4.1.3-09
func TestUnknownCodeIsRejected(t *testing.T) {
	a := newAuthorizationServer(t)
	status, _, body := a.token(tokenParams("unknown"), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestCodeReturnsAccessTokenOnce checks that concurrent token requests with one code return at most one access token.
//
//conformance:covers OAUTH21D16-4.1.3-05
func TestCodeReturnsAccessTokenOnce(t *testing.T) {
	a := newAuthorizationServer(t)
	if issued := a.race(tokenParams(a.code(authorizeParams()))); len(issued) > 1 {
		t.Fatalf("got %d access tokens for one code, want at most 1", len(issued))
	}
}

// wantSecondRedemptionDenied redeems a code of the public Client and checks that redeeming it again gets invalid_grant.
func (a *authorizationServer) wantSecondRedemptionDenied() {
	a.t.Helper()
	params := tokenParams(a.code(authorizeParams()))
	a.tokens(params, nil)
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestSecondRedemptionIsDenied checks that a second valid token request with a redeemed code gets invalid_grant.
//
//conformance:covers OAUTH21D16-4.1.3-06
func TestSecondRedemptionIsDenied(t *testing.T) {
	newAuthorizationServer(t).wantSecondRedemptionDenied()
}

// TestCodeReplayRevokesAccessToken checks that a second valid redemption of a code revokes the access token issued from it.
//
//conformance:covers OAUTH21D16-4.1.3-07
func TestCodeReplayRevokesAccessToken(t *testing.T) {
	a := newIntrospectionServer(t)
	params := tokenParams(a.code(authorizeParams()))
	access, _ := a.tokens(params, nil)
	a.token(params, nil)
	a.wantInactive(access)
}

// TestAccessTokenIsStoredAsHash checks that the Stores receive only the hash of an access token, also when it is validated and revoked.
//
//conformance:covers OAUTH21D16-1.4-02
func TestAccessTokenIsStoredAsHash(t *testing.T) {
	a := newIntrospectionServer(t)
	a.resource(a.local())
	code := a.code(authorizeParams())
	access, refresh := a.tokens(tokenParams(code), nil)
	a.introspect(access)
	a.access(bearerHeader(access))
	a.revoke(revocationParams(access), nil)
	a.wantStoredOnlyAsHashes(code, access, refresh)
}

// TestRefreshTokenIsStoredAsHash checks that the Stores receive only the hash of a refresh token, also when it is rotated and revoked.
//
//conformance:covers OAUTH21D16-4.3-01
func TestRefreshTokenIsStoredAsHash(t *testing.T) {
	a := newAuthorizationServer(t)
	code := a.code(authorizeParams())
	access, refresh := a.tokens(tokenParams(code), nil)
	refreshed, next := a.tokens(refreshParams(refresh), nil)
	a.revoke(revocationParams(next), nil)
	a.wantStoredOnlyAsHashes(code, access, refresh, refreshed, next)
}

// TestTokenRequestMayCarryRedirectURI checks that a code redeems when the token request repeats the redirect_uri of the authorization request.
//
//conformance:covers OAUTH21D16-10.2-01
func TestTokenRequestMayCarryRedirectURI(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	params.Set("redirect_uri", redirectURI)
	if status, _, body := a.token(params, nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v, want 200", status, body)
	}
}

// TestUnknownTokenParameterIsIgnored checks that a token request with an unrecognized parameter succeeds.
//
//conformance:covers OAUTH21D16-3.2-04
func TestUnknownTokenParameterIsIgnored(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	params.Set("unknown", "value")
	a.tokens(params, nil)
}

// TestEmptyTokenParameterIsOmitted checks that a refresh request with a scope parameter without a value gets the granted scope.
//
//conformance:covers OAUTH21D16-3.2-05
func TestEmptyTokenParameterIsOmitted(t *testing.T) {
	a := newAuthorizationServer(t)
	authorize := authorizeParams()
	authorize.Set("scope", "read write")
	_, refresh := a.tokens(tokenParams(a.code(authorize)), nil)
	params := refreshParams(refresh)
	params.Set("scope", "")
	if status, _, body := a.token(params, nil); status != http.StatusOK || body["scope"] != "read write" {
		t.Fatalf("got status %d and body %v, want scope read write", status, body)
	}
}

// TestRepeatedTokenParameterIsRejected checks that a token request with a repeated parameter gets invalid_request.
//
//conformance:covers OAUTH21D16-3.2-06
func TestRepeatedTokenParameterIsRejected(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	params.Add("code_verifier", strings.Repeat("v", 43))
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestTokenRequestRequiresGrantType checks that a token request without grant_type gets invalid_request.
//
//conformance:covers OAUTH21D16-3.2.2-01
func TestTokenRequestRequiresGrantType(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	params.Del("grant_type")
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestTokenRequestRequiresCode checks that a code redemption without code gets invalid_request.
//
//conformance:covers OAUTH21D16-4.1.3-01
func TestTokenRequestRequiresCode(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	params.Del("code")
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestRefreshRequiresRefreshToken checks that a refresh request without refresh_token gets invalid_request.
//
//conformance:covers OAUTH21D16-4.3.1-01
func TestRefreshRequiresRefreshToken(t *testing.T) {
	a := newAuthorizationServer(t)
	params := refreshParams(a.publicRefreshToken())
	params.Del("refresh_token")
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestTokenResponsesAreNotStored checks that successful and failed token responses carry Cache-Control no-store.
//
//conformance:covers OAUTH21D16-3.2.3-12
func TestTokenResponsesAreNotStored(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	for range 2 {
		if status, header, _ := a.token(params, nil); header.Get("Cache-Control") != "no-store" {
			t.Fatalf("got status %d and Cache-Control %q, want no-store", status, header.Get("Cache-Control"))
		}
	}
}

// TestClientSecretRequiresClientID checks that a client_secret without client_id does not authenticate.
//
//conformance:covers OAUTH21D16-2.4.1-02
func TestClientSecretRequiresClientID(t *testing.T) {
	a := newServiceServer(t)
	params := clientCredentialsParams("")
	params.Set("client_secret", secret)
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
}

// TestCredentialsInURIAreIgnored checks that client_id and client_secret in the request URI do not authenticate.
//
//conformance:covers OAUTH21D16-2.4.1-04
func TestCredentialsInURIAreIgnored(t *testing.T) {
	a := newServiceServer(t)
	query := url.Values{"client_id": {serviceID}, "client_secret": {secret}}
	status, _, body := a.sendJSON(http.MethodPost, "/token?"+query.Encode(), clientCredentialsParams("").Encode(), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
}

// TestEndpointsRequirePost checks that the token, revocation and introspection endpoints answer GET requests with invalid_request.
//
//conformance:covers INV-0006
func TestEndpointsRequirePost(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	for _, r := range []struct {
		path   string
		params url.Values
		header http.Header
	}{
		{"/token", tokenParams(a.code(authorizeParams())), nil},
		{"/revoke", revocationParams(access), nil},
		{"/introspect", url.Values{"token": {access}}, basic(resourceServerID, secret)},
	} {
		status, _, body := a.sendJSON(http.MethodGet, r.path+"?"+r.params.Encode(), "", r.header)
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
	}
}

// random returns a value of the form of the codes and tokens the server issues that it never issued.
func random(t *testing.T) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// randomWithHash returns random(t) and its SHA-256 hash, the key a Store holds a code or token by.
func randomWithHash(t *testing.T) (string, []byte) {
	value := random(t)
	sum := sha256.Sum256([]byte(value))
	return value, sum[:]
}

// aliceGrant returns a Grant of alice and the public Client with scope read and audience.
func aliceGrant(id string, audience ...string) store.Grant {
	return store.Grant{ID: id, ClientID: clientID, Subject: "alice", Scopes: readScope, Audience: audience}
}

// flipped returns v with its first character changed.
func flipped(v string) string {
	if v[0] == 'A' {
		return "B" + v[1:]
	}
	return "A" + v[1:]
}

// TestGeneratedAccessTokenIsInactive checks that a value of the form of an access token that the server did not issue introspects as inactive.
//
//conformance:covers OAUTH21D16-1.4-03
func TestGeneratedAccessTokenIsInactive(t *testing.T) {
	a := newIntrospectionServer(t)
	a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.wantInactive(random(t))
}

// TestModifiedAccessTokenIsInactive checks that an access token changed in one character introspects as inactive.
//
//conformance:covers OAUTH21D16-1.4-06
func TestModifiedAccessTokenIsInactive(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.wantInactive(flipped(access))
}

// TestGeneratedRefreshTokenIsRejected checks that a value of the form of a refresh token that the server did not issue gets invalid_grant.
//
//conformance:covers OAUTH21D16-4.3-05
func TestGeneratedRefreshTokenIsRejected(t *testing.T) {
	a := newAuthorizationServer(t)
	a.publicRefreshToken()
	status, _, body := a.token(refreshParams(random(t)), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestModifiedRefreshTokenIsRejected checks that a refresh token changed in one character gets invalid_grant.
//
//conformance:covers OAUTH21D16-4.3-08
func TestModifiedRefreshTokenIsRejected(t *testing.T) {
	a := newAuthorizationServer(t)
	status, _, body := a.token(refreshParams(flipped(a.publicRefreshToken())), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// spliced returns the first half of a joined with the second half of b.
func spliced(a, b string) string {
	return a[:len(a)/2] + b[len(b)/2:]
}

// TestSplicedAccessTokenIsInactive checks that joining halves of two access tokens does not give an active access token.
//
//conformance:covers OAUTH21D16-1.4.2-03
func TestSplicedAccessTokenIsInactive(t *testing.T) {
	a := newIntrospectionServer(t)
	first, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	second, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.wantInactive(spliced(first, second))
}

// TestSplicedRefreshTokenIsRejected checks that joining halves of refresh tokens of two Grants does not give a refresh token.
//
//conformance:covers OAUTH21D16-4.3.1-07
func TestSplicedRefreshTokenIsRejected(t *testing.T) {
	a := newAuthorizationServer(t)
	status, _, body := a.token(refreshParams(spliced(a.publicRefreshToken(), a.publicRefreshToken())), nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestAccessTokenRevealsNothing checks that an access token carries nothing of its Grant: with the same randomness source, Grants of different subjects and scopes get the same access token.
//
//conformance:covers OAUTH21D16-7.1.1.2-01
func TestAccessTokenRevealsNothing(t *testing.T) {
	var tokens []string
	for subject, scope := range map[string]string{"alice": "read", "bob": "write"} {
		a := newSeededServer(t, &seededRandom{seed: 1})
		params := authorizeParams()
		params.Set("scope", scope)
		req := a.pending(a.authorize(params))
		u := a.complete(req.ID, oauth21.Completion{Subject: subject, Scopes: []string{scope}})
		access, _ := a.tokens(tokenParams(u.Query().Get("code")), nil)
		tokens = append(tokens, access)
	}
	if tokens[0] != tokens[1] {
		t.Fatalf("got access tokens %q for two Grants, want the same token", tokens)
	}
}

// issuing runs requests on a with randomness source s and returns the value one of them issues, and the range of bytes read from s while that request ran.
type issuing func(a *authorizationServer, s *seededRandom) (value string, from, to int)

// wantUnguessable checks that a value issue issues carries at least 128 bits of randomness: the same randomness reproduces it, and at least 128 of the bits the server reads while issuing it change it when inverted.
func wantUnguessable(t *testing.T, issue issuing) {
	t.Helper()
	run := func(t *testing.T, flip int) (string, int, int) {
		s := &seededRandom{seed: 1, flip: flip}
		return issue(newSeededServer(t, s, serviceClients(t)...), s)
	}
	value, from, to := run(t, 0)
	if again, _, _ := run(t, 0); again != value {
		t.Fatalf("got %q and %q from the same randomness, want the same value", value, again)
	}
	changed := 0
	for bit := from*8 + 1; bit <= to*8 && changed < 128; bit++ {
		t.Run(fmt.Sprintf("bit %d", bit), func(t *testing.T) {
			if v, _, _ := run(t, bit); v != value {
				changed++
			}
		})
	}
	if changed < 128 {
		t.Fatalf("got %d bits of randomness changing %q, want at least 128", changed, value)
	}
}

// while returns how many bytes do reads from s, as the range from the bytes read before to the bytes read after.
func while(s *seededRandom, do func()) (from, to int) {
	from = s.bytesRead()
	do()
	return from, s.bytesRead()
}

// clientCredentialsAccess issues an access token to the service Client with client credentials.
func clientCredentialsAccess(a *authorizationServer, s *seededRandom) (access string, from, to int) {
	from, to = while(s, func() { access, _ = a.tokens(clientCredentialsParams(""), basic(serviceID, secret)) })
	return access, from, to
}

// completedCode issues a code by completing an Authorization Request of the public Client.
func completedCode(a *authorizationServer, s *seededRandom) (code string, from, to int) {
	req := a.pending(a.authorize(authorizeParams()))
	from, to = while(s, func() {
		code = a.complete(req.ID, oauth21.Completion{Subject: "alice", Scopes: readScope}).Query().Get("code")
	})
	return code, from, to
}

// redeemed redeems a code of the public Client and returns its access token or, when refresh is set, its refresh token.
func redeemed(refresh bool) issuing {
	return func(a *authorizationServer, s *seededRandom) (string, int, int) {
		params := tokenParams(a.code(authorizeParams()))
		var access, rt string
		from, to := while(s, func() { access, rt = a.tokens(params, nil) })
		if refresh {
			return rt, from, to
		}
		return access, from, to
	}
}

// refreshed refreshes a refresh token of the public Client and returns the new access token or, when refresh is set, the new refresh token.
func refreshed(refresh bool) issuing {
	return func(a *authorizationServer, s *seededRandom) (string, int, int) {
		params := refreshParams(a.publicRefreshToken())
		var access, rt string
		from, to := while(s, func() { access, rt = a.tokens(params, nil) })
		if refresh {
			return rt, from, to
		}
		return access, from, to
	}
}

// TestClientCredentialsAccessTokenCannotBeGuessed checks that an access token issued for client credentials carries at least 128 bits of randomness.
//
//conformance:covers OAUTH21D16-1.4-07
func TestClientCredentialsAccessTokenCannotBeGuessed(t *testing.T) {
	wantUnguessable(t, clientCredentialsAccess)
}

// TestRefreshedAccessTokenIsUnguessableReference checks that an access token issued by a refresh, a reference to its Grant, carries at least 128 bits of randomness.
//
//conformance:covers OAUTH21D16-1.4.2-02
func TestRefreshedAccessTokenIsUnguessableReference(t *testing.T) {
	wantUnguessable(t, refreshed(false))
}

// TestRedeemedAccessTokenCannotBeGuessed checks that an access token issued for a code carries at least 128 bits of randomness.
//
//conformance:covers OAUTH21D16-7.7-01
func TestRedeemedAccessTokenCannotBeGuessed(t *testing.T) {
	wantUnguessable(t, redeemed(false))
}

// TestCodeCannotBeGuessed checks that a code carries at least 128 bits of randomness.
//
//conformance:covers OAUTH21D16-7.7-07
func TestCodeCannotBeGuessed(t *testing.T) {
	wantUnguessable(t, completedCode)
}

// TestRotatedRefreshTokenCannotBeGuessed checks that a refresh token issued by a refresh carries at least 128 bits of randomness.
//
//conformance:covers OAUTH21D16-7.7-08
func TestRotatedRefreshTokenCannotBeGuessed(t *testing.T) {
	wantUnguessable(t, refreshed(true))
}

// TestRedeemedRefreshTokenCannotBeGuessed checks that a refresh token issued for a code carries at least 128 bits of randomness.
//
//conformance:covers OAUTH21D16-4.3-09
func TestRedeemedRefreshTokenCannotBeGuessed(t *testing.T) {
	wantUnguessable(t, redeemed(true))
}

// TestIssuedValuesCarry128Bits checks that codes, access tokens and refresh tokens each carry at least 128 bits of randomness, so guessing one succeeds with a probability of at most 2^-128.
//
//conformance:covers OAUTH21D16-7.7-02
func TestIssuedValuesCarry128Bits(t *testing.T) {
	for name, issue := range map[string]issuing{"code": completedCode, "access token": redeemed(false), "refresh token": redeemed(true)} {
		t.Run(name, func(t *testing.T) { wantUnguessable(t, issue) })
	}
}

// responses runs a full flow on a newIntrospectionServer: authorization, completion, redemption, refresh, introspection, a Bearer request and revocation, and returns the headers of every response.
func (a *authorizationServer) responses() []http.Header {
	a.t.Helper()
	a.resource(a.local())
	var headers []http.Header
	record := func(_ int, h http.Header, _ []byte) { headers = append(headers, h) }
	_, login := a.sendAuthorization(authorizeParams())
	u := a.login(a.redirect(login), "alice")
	record(a.send(http.MethodPost, "/token", tokenParams(u.Query().Get("code")).Encode(), nil))
	access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	record(a.send(http.MethodPost, "/token", refreshParams(refresh).Encode(), nil))
	record(a.send(http.MethodPost, "/introspect", url.Values{"token": {access}}.Encode(), basic(resourceServerID, secret)))
	record(a.access(bearerHeader(access)))
	record(a.send(http.MethodPost, "/revoke", revocationParams(access).Encode(), nil))
	record(a.send(http.MethodGet, "/authorize?"+authorizeParams().Encode(), "", nil))
	return headers
}

// wantNoCookies checks that no response of a full flow sets a cookie.
func (a *authorizationServer) wantNoCookies() {
	a.t.Helper()
	for _, h := range a.responses() {
		if c := h.Values("Set-Cookie"); len(c) > 0 {
			a.t.Fatalf("got Set-Cookie %q, want no cookies", c)
		}
	}
}

// TestBearerTokensAreNotInCookies checks that no response sets a cookie that could carry a Bearer token in the clear.
//
//conformance:covers OAUTH21D16-7.1.1.2-02
func TestBearerTokensAreNotInCookies(t *testing.T) {
	newIntrospectionServer(t).wantNoCookies()
}

// TestBearerTokensAreNotStoredInCookies checks that the library stores no Bearer token in a cookie.
//
//conformance:covers OAUTH21D16-7.1.3.4-01
func TestBearerTokensAreNotStoredInCookies(t *testing.T) {
	newIntrospectionServer(t).wantNoCookies()
}

// TestNoCookieNeedsCSRFProtection checks that no response sets a cookie, so no cookie carries a token that needs protection against cross-site request forgery.
//
//conformance:covers OAUTH21D16-7.1.3.4-02
func TestNoCookieNeedsCSRFProtection(t *testing.T) {
	newIntrospectionServer(t).wantNoCookies()
}

// uriReference reports whether s is a URI-reference (RFC 3986 4.1): only unreserved and reserved characters and percent-encodings.
func uriReference(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 2
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', strings.IndexByte("-._~:/?#[]@!$&'()*+,;=", c) >= 0:
		default:
			return false
		}
	}
	_, err := url.Parse(s)
	return s != "" && err == nil
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// uriChars reports whether s has only the characters %x21 / %x23-5B / %x5D-7E that error_uri values may have.
func uriChars(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e || r == '"' || r == '\\' })
}

// TestTokenErrorURIIsURIReference checks that a token error response carries error_uri only as a URI-reference.
//
//conformance:covers OAUTH21D16-3.2.4-08
func TestTokenErrorURIIsURIReference(t *testing.T) {
	a := newConfidentialServer(t)
	for _, body := range a.tokenErrors() {
		if v, ok := body["error_uri"]; ok {
			if s, _ := v.(string); !uriReference(s) {
				t.Fatalf("got error_uri %v, want a URI-reference", v)
			}
		}
	}
}

// TestTokenErrorURICharacters checks that a token error response carries error_uri only with the allowed characters.
//
//conformance:covers OAUTH21D16-3.2.4-09
func TestTokenErrorURICharacters(t *testing.T) {
	a := newConfidentialServer(t)
	for _, body := range a.tokenErrors() {
		if v, ok := body["error_uri"]; ok {
			if s, _ := v.(string); !uriChars(s) {
				t.Fatalf("got error_uri %v, want only the allowed characters", v)
			}
		}
	}
}
