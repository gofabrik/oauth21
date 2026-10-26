package conformance

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"maps"
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

// tokenErrors returns the bodies of failing token requests on a newServiceServer, some with characters outside those error values may have.
func (a *authorizationServer) tokenErrors() []map[string]any {
	a.t.Helper()
	grant := tokenParams("")
	grant.Set("grant_type", "päss\"word\\")
	unknownClient := tokenParams(a.code(authorizeParams()))
	unknownClient.Set("client_id", "clïent\"\\")
	otherRedirect := tokenParams(a.code(authorizeParams()))
	otherRedirect.Set("redirect_uri", "https://client.example/cb?ü=\"\\")
	var bodies []map[string]any
	for _, r := range []struct {
		params url.Values
		header http.Header
	}{
		{tokenParams("cöde\"\\"), nil},
		{withVerifier(tokenParams(a.code(authorizeParams())), ""), nil},
		{grant, nil},
		{clientCredentialsParams("read ünknown\"\\"), basic(serviceID, secret)},
		{a.confidentialCode(), basic(confidentialID, "wrong")},
		{unknownClient, nil},
		{otherRedirect, nil},
		{withVerifier(tokenParams(a.code(authorizeParams())), "vérifier\"\\"), nil},
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
	a := newServiceServer(t)
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
	a := newServiceServer(t)
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
	a := newServiceServer(t)
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

// TestEmptyTokenParameterIsOmitted checks that a refresh request with a scope parameter without a value gets the granted scope, and one that also has the scope parameter with a value gets that scope.
//
//conformance:covers OAUTH21D16-3.2-05
func TestEmptyTokenParameterIsOmitted(t *testing.T) {
	a := newAuthorizationServer(t)
	authorize := authorizeParams()
	authorize.Set("scope", "read write")
	_, refresh := a.tokens(tokenParams(a.code(authorize)), nil)
	params := refreshParams(refresh)
	params.Set("scope", "")
	status, _, body := a.token(params, nil)
	if status != http.StatusOK || body["scope"] != "read write" {
		t.Fatalf("got status %d and body %v, want scope read write", status, body)
	}
	next, _ := body["refresh_token"].(string)
	params = refreshParams(next)
	params["scope"] = []string{"read", ""}
	if status, _, body := a.token(params, nil); status != http.StatusOK || body["scope"] != "read" {
		t.Fatalf("got status %d and body %v, want scope read", status, body)
	}
}

// TestRepeatedTokenParameterIsRejected checks that a token request with a repeated parameter gets invalid_request, with another or the same value.
//
//conformance:covers OAUTH21D16-3.2-06
func TestRepeatedTokenParameterIsRejected(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	for _, repeated := range []string{strings.Repeat("v", 43), verifier} {
		p := maps.Clone(params)
		p["code_verifier"] = []string{verifier, repeated}
		status, _, body := a.token(p, nil)
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
	}
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

// TestPasswordGrantIsUnsupported checks that a password grant request gets unsupported_grant_type, even from a Client whose grant types list password.
//
//conformance:covers INV-0015
func TestPasswordGrantIsUnsupported(t *testing.T) {
	client := confidentialClient(t)
	client.GrantTypes = []string{"password"}
	a := newAuthorizationServer(t, client)
	params := url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"hunter2"}}
	status, _, body := a.token(params, basic(confidentialID, secret))
	a.wantOAuthError(status, body, http.StatusBadRequest, "unsupported_grant_type")
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

// TestTokenResponsesAreNotStored checks that successful and failed token responses and active introspection responses carry Cache-Control no-store.
//
//conformance:covers OAUTH21D16-3.2.3-12
func TestTokenResponsesAreNotStored(t *testing.T) {
	a := newIntrospectionServer(t)
	wantNoStore := func(status int, header http.Header, body map[string]any) {
		t.Helper()
		if header.Get("Cache-Control") != "no-store" {
			t.Fatalf("got status %d, body %v and Cache-Control %q, want no-store", status, body, header.Get("Cache-Control"))
		}
	}
	params := tokenParams(a.code(authorizeParams()))
	status, header, body := a.token(params, nil)
	wantNoStore(status, header, body)
	access, _ := body["access_token"].(string)
	status, header, body = a.sendJSON(http.MethodPost, "/introspect", url.Values{"token": {access}}.Encode(), basic(resourceServerID, secret))
	if body["active"] != true {
		t.Fatalf("got status %d and body %v, want an active token", status, body)
	}
	wantNoStore(status, header, body)
	wantNoStore(a.token(params, nil))
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

// TestCredentialsInURIAreIgnored checks that client_id and client_secret in the request URI do not authenticate, also with client_id in the body.
//
//conformance:covers OAUTH21D16-2.4.1-04
func TestCredentialsInURIAreIgnored(t *testing.T) {
	a := newServiceServer(t)
	withClientID := clientCredentialsParams("")
	withClientID.Set("client_id", serviceID)
	for query, params := range map[string]url.Values{
		url.Values{"client_id": {serviceID}, "client_secret": {secret}}.Encode(): clientCredentialsParams(""),
		url.Values{"client_secret": {secret}}.Encode():                           withClientID,
	} {
		status, _, body := a.sendJSON(http.MethodPost, "/token?"+query, params.Encode(), nil)
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
	}
}

// TestEndpointsRequirePost checks that the token, revocation and introspection endpoints answer GET, PUT, PATCH and DELETE requests with invalid_request.
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
		header := r.header.Clone()
		if header == nil {
			header = http.Header{}
		}
		header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
			status, _, body := a.sendJSON(method, r.path, r.params.Encode(), header)
			a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
		}
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

// sharingHashPrefix returns a value of the form of the codes and tokens the server issues whose hash starts with the first two bytes of the hash of v.
func sharingHashPrefix(t *testing.T, v string) string {
	want := sha256.Sum256([]byte(v))
	for {
		if value, hash := randomWithHash(t); bytes.Equal(hash[:2], want[:2]) {
			return value
		}
	}
}

// base64URL is the base64url alphabet, in the order of its values.
const base64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// modified returns copies of the base64url value v with the lowest bit of its first, middle and last character inverted.
func modified(v string) []string {
	var values []string
	for _, i := range []int{0, len(v) / 2, len(v) - 1} {
		c := base64URL[strings.IndexByte(base64URL, v[i])^1]
		values = append(values, v[:i]+string(c)+v[i+1:])
	}
	return values
}

// TestGeneratedAccessTokenIsInactive checks that values of the form of an access token that the server did not issue introspect as inactive, also one whose hash starts like the hash of an issued one.
//
//conformance:covers OAUTH21D16-1.4-03
func TestGeneratedAccessTokenIsInactive(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	a.wantInactive(random(t))
	a.wantInactive(sharingHashPrefix(t, access))
}

// TestModifiedAccessTokenIsInactive checks that an access token changed in one bit of its first, middle or last character introspects as inactive.
//
//conformance:covers OAUTH21D16-1.4-06
func TestModifiedAccessTokenIsInactive(t *testing.T) {
	a := newIntrospectionServer(t)
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	for _, v := range modified(access) {
		a.wantInactive(v)
	}
}

// TestGeneratedRefreshTokenIsRejected checks that values of the form of a refresh token that the server did not issue get invalid_grant, also one whose hash starts like the hash of an issued one.
//
//conformance:covers OAUTH21D16-4.3-05
func TestGeneratedRefreshTokenIsRejected(t *testing.T) {
	a := newAuthorizationServer(t)
	refresh := a.publicRefreshToken()
	for _, v := range []string{random(t), sharingHashPrefix(t, refresh)} {
		status, _, body := a.token(refreshParams(v), nil)
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	}
}

// TestModifiedRefreshTokenIsRejected checks that a refresh token changed in one bit of its first, middle or last character gets invalid_grant.
//
//conformance:covers OAUTH21D16-4.3-08
func TestModifiedRefreshTokenIsRejected(t *testing.T) {
	a := newAuthorizationServer(t)
	refresh := a.publicRefreshToken()
	for _, v := range modified(refresh) {
		status, _, body := a.token(refreshParams(v), nil)
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	}
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

// TestAccessTokenRevealsNothing checks that an access token carries nothing of its Grant: with the same randomness source, Grants of different Clients, subjects and scopes get the same access token.
//
//conformance:covers OAUTH21D16-7.1.1.2-01
func TestAccessTokenRevealsNothing(t *testing.T) {
	confidential := confidentialClient(t)
	confidential.AllowedScopes = []string{"read", "write"}
	var tokens []string
	for _, g := range []struct {
		client, subject, scope string
		header                 http.Header
	}{
		{clientID, "alice", "read", nil},
		{confidentialID, "bob", "write", basic(confidentialID, secret)},
	} {
		a := newSeededServer(t, &seededRandom{seed: 1}, confidential)
		params := authorizeParams()
		params.Set("client_id", g.client)
		params.Set("scope", g.scope)
		req := a.pending(a.authorize(params))
		u := a.complete(req.ID, oauth21.Completion{Subject: g.subject, Scopes: []string{g.scope}})
		token := tokenParams(u.Query().Get("code"))
		if g.header != nil {
			token.Del("client_id")
		}
		access, _ := a.tokens(token, g.header)
		tokens = append(tokens, access)
	}
	if tokens[0] != tokens[1] {
		t.Fatalf("got access tokens %q for two Grants, want the same token", tokens)
	}
}

// minUnguessableLength is the fewest URL-safe characters that hold 128 bits.
const minUnguessableLength = 22

// issuing runs requests on a with randomness source s and returns the value one of them issues, and the range of bytes read from s while that request ran.
type issuing func(a *authorizationServer, s *seededRandom) (value string, from, to int)

// wantUnguessable checks that a value issue issues carries at least 128 bits of randomness: it is long enough to hold them, the same randomness reproduces it, and at least 128 of the bits the server reads while issuing it change it when inverted, no two to the same value.
func wantUnguessable(t *testing.T, issue issuing) {
	t.Helper()
	run := func(t *testing.T, flip int) (string, int, int) {
		s := &seededRandom{seed: 1, flip: flip}
		return issue(newSeededServer(t, s, serviceClients(t)...), s)
	}
	value, from, to := run(t, 0)
	if len(value) < minUnguessableLength {
		t.Fatalf("got %q of %d characters, want at least %d to hold 128 bits", value, len(value), minUnguessableLength)
	}
	if again, _, _ := run(t, 0); again != value {
		t.Fatalf("got %q and %q from the same randomness, want the same value", value, again)
	}
	changedBy := map[string]int{}
	for bit := from*8 + 1; bit <= to*8 && len(changedBy) < 128; bit++ {
		t.Run(fmt.Sprintf("bit %d", bit), func(t *testing.T) {
			v, _, _ := run(t, bit)
			if v == value {
				return
			}
			if other, ok := changedBy[v]; ok {
				t.Fatalf("got %q when inverting bit %d and bit %d, want different values", v, other, bit)
			}
			changedBy[v] = bit
		})
	}
	if n := len(changedBy); n < 128 {
		t.Fatalf("got %d bits of randomness changing %q, want at least 128", n, value)
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

// requestID issues the ID of an Authorization Request of the public Client.
func requestID(a *authorizationServer, s *seededRandom) (id string, from, to int) {
	from, to = while(s, func() { id = a.authorize(authorizeParams()).Query().Get("request_id") })
	return id, from, to
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

// codeAndTokenIssuers returns the issuers of a code and of the access token and refresh token redeemed for it.
func codeAndTokenIssuers() map[string]issuing {
	return map[string]issuing{"code": completedCode, "access token": redeemed(false), "refresh token": redeemed(true)}
}

// TestIssuedValuesCarry128Bits checks that codes, access tokens and refresh tokens each carry at least 128 bits of randomness, so guessing one succeeds with a probability of at most 2^-128.
//
//conformance:covers OAUTH21D16-7.7-02
func TestIssuedValuesCarry128Bits(t *testing.T) {
	for name, issue := range codeAndTokenIssuers() {
		t.Run(name, func(t *testing.T) { wantUnguessable(t, issue) })
	}
}

// TestEveryIssuedValueCarries128Bits checks that Authorization Request IDs, codes, access tokens and refresh tokens, issued in every way the server issues them, each carry at least 128 bits of randomness.
//
//conformance:covers INV-0014
func TestEveryIssuedValueCarries128Bits(t *testing.T) {
	issuers := codeAndTokenIssuers()
	maps.Copy(issuers, map[string]issuing{
		"request ID":               requestID,
		"refreshed access token":   refreshed(false),
		"refreshed refresh token":  refreshed(true),
		"client credentials token": clientCredentialsAccess,
	})
	for name, issue := range issuers {
		t.Run(name, func(t *testing.T) { wantUnguessable(t, issue) })
	}
}

// newFlowServer starts an Authorization Server with the Clients of newIntrospectionServer and the service Client, which may use client credentials.
func newFlowServer(t *testing.T) *authorizationServer {
	t.Helper()
	return newAuthorizationServer(t, append(newIntrospectionClients(t), serviceClient(t))...)
}

// responses runs every kind of request on a newFlowServer, failed ones included, and returns the headers of every response.
func (a *authorizationServer) responses() []http.Header {
	a.t.Helper()
	a.resource(a.local())
	var headers []http.Header
	record := func(_ int, h http.Header, _ []byte) { headers = append(headers, h) }
	_, login := a.sendAuthorization(authorizeParams())
	u := a.login(a.redirect(login), "alice")
	redemption := tokenParams(u.Query().Get("code")).Encode()
	record(a.send(http.MethodPost, "/token", redemption, nil))
	record(a.send(http.MethodPost, "/token", redemption, nil))
	record(a.send(http.MethodPost, "/token", clientCredentialsParams("").Encode(), basic(serviceID, secret)))
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
	newFlowServer(t).wantNoCookies()
}

// TestBearerTokensAreNotStoredInCookies checks that the library stores no Bearer token in a cookie.
//
//conformance:covers OAUTH21D16-7.1.3.4-01
func TestBearerTokensAreNotStoredInCookies(t *testing.T) {
	newFlowServer(t).wantNoCookies()
}

// TestNoCookieNeedsCSRFProtection checks that no response sets a cookie, so no cookie carries a token that needs protection against cross-site request forgery.
//
//conformance:covers OAUTH21D16-7.1.3.4-02
func TestNoCookieNeedsCSRFProtection(t *testing.T) {
	newFlowServer(t).wantNoCookies()
}

// uriReference reports whether s is a URI-reference (RFC 3986 4.1): only unreserved and reserved characters and percent-encodings, at most one "#", and brackets only around an IP-literal host.
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
	u, err := url.Parse(s)
	if s == "" || err != nil || strings.Count(s, "#") > 1 {
		return false
	}
	if strings.Contains(u.Host, "[") && (!strings.HasPrefix(u.Host, "[") || u.Hostname() == "") {
		return false
	}
	return !strings.ContainsAny(strings.Replace(s, u.Host, "", 1), "[]")
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
	a := newServiceServer(t)
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
	a := newServiceServer(t)
	for _, body := range a.tokenErrors() {
		if v, ok := body["error_uri"]; ok {
			if s, _ := v.(string); !uriChars(s) {
				t.Fatalf("got error_uri %v, want only the allowed characters", v)
			}
		}
	}
}

// TestPasswordGrantCannotBeUsed checks that a resource owner password credentials grant issues no tokens, to a public Client or to a confidential Client whose grant types list password.
//
//conformance:covers RFC9700-2.4-01
func TestPasswordGrantCannotBeUsed(t *testing.T) {
	client := confidentialClient(t)
	client.GrantTypes = []string{"password"}
	a := newAuthorizationServer(t, client)
	confidential := url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"hunter2"}, "scope": {"read"}}
	public := url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"hunter2"}, "client_id": {clientID}}
	for _, req := range []struct {
		params url.Values
		header http.Header
	}{{confidential, basic(confidentialID, secret)}, {public, nil}} {
		if status, _, body := a.token(req.params, req.header); status == http.StatusOK || body["access_token"] != nil || body["refresh_token"] != nil {
			t.Fatalf("got status %d and body %v, want an error without tokens", status, body)
		}
	}
}

// TestRefreshTokenIntegrityIsVerified checks that a refresh token assembled from parts of others, or with one character changed, does not refresh.
//
//conformance:covers RFC9700-4.14.2-05
func TestRefreshTokenIntegrityIsVerified(t *testing.T) {
	a := newAuthorizationServer(t)
	first, second := a.publicRefreshToken(), a.publicRefreshToken()
	changed := []byte(first)
	changed[len(changed)-1] ^= 1
	for _, v := range []string{spliced(first, second), spliced(second, first), string(changed)} {
		status, _, body := a.token(refreshParams(v), nil)
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
	}
}
