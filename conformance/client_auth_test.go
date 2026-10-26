package conformance

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/store"
)

const (
	confidentialID = "confidential client"
	secret         = "s3cret+/:%"
)

// newConfidentialServer starts an Authorization Server with a confidential Client that has secret.
func newConfidentialServer(t *testing.T) *authorizationServer {
	t.Helper()
	return newAuthorizationServer(t, confidentialClient(t))
}

// confidentialClient returns the confidential Client that has secret.
func confidentialClient(t *testing.T) store.Client {
	t.Helper()
	hash, err := oauth21.PBKDF2{Iterations: 1000}.Hash(secret)
	if err != nil {
		t.Fatal(err)
	}
	return store.Client{ID: confidentialID, Type: store.Confidential, RedirectURIs: []string{redirectURI}, AllowedScopes: readScope, DefaultScopes: readScope, SecretHash: hash}
}

// confidentialCode runs an authorization request of the confidential Client and returns its token request without credentials.
func (a *authorizationServer) confidentialCode() url.Values {
	params := authorizeParams()
	params.Set("client_id", confidentialID)
	token := tokenParams(a.code(params))
	token.Del("client_id")
	return token
}

// basic returns an Authorization header carrying id and secret as client_secret_basic.
func basic(id, secret string) http.Header {
	header := http.Header{}
	header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret))))
	return header
}

// TestConfidentialClientAuthenticates checks that client_secret_basic accepts several spaces after the scheme and a client_id in the request content.
func TestConfidentialClientAuthenticates(t *testing.T) {
	t.Run("client_secret_basic with several spaces", func(t *testing.T) {
		a := newConfidentialServer(t)
		header := basic(confidentialID, secret)
		header.Set("Authorization", strings.Replace(header.Get("Authorization"), " ", "   ", 1))
		status, _, body := a.token(a.confidentialCode(), header)
		if status != http.StatusOK {
			t.Fatalf("got status %d and body %v, want 200", status, body)
		}
	})
	t.Run("client_secret_basic with client_id", func(t *testing.T) {
		a := newConfidentialServer(t)
		params := a.confidentialCode()
		params.Set("client_id", confidentialID)
		status, _, body := a.token(params, basic(confidentialID, secret))
		if status != http.StatusOK {
			t.Fatalf("got status %d and body %v, want 200", status, body)
		}
	})
}

// TestFailedClientAuthentication checks that failed authentication gets invalid_client, as a 401 with a Basic challenge when the Authorization header was used.
//
//conformance:covers OAUTH21D16-3.2.2-05
func TestFailedClientAuthentication(t *testing.T) {
	tests := map[string]struct {
		header    http.Header
		form      url.Values
		challenge string
	}{
		"wrong Basic secret":       {basic(confidentialID, "wrong"), nil, `Basic realm="oauth21"`},
		"upper-cased Basic secret": {basic(confidentialID, strings.ToUpper(secret)), nil, `Basic realm="oauth21"`},
		"extended Basic secret":    {basic(confidentialID, secret+"x"), nil, `Basic realm="oauth21"`},
		"truncated Basic secret":   {basic(confidentialID, secret[:len(secret)-1]), nil, `Basic realm="oauth21"`},
		"unencoded Basic secret":   {basic(confidentialID, url.QueryEscape(secret)), nil, `Basic realm="oauth21"`},
		"unknown Basic client":     {basic("unknown", secret), nil, `Basic realm="oauth21"`},
		"malformed Basic":          {http.Header{"Authorization": {"Basic !"}}, nil, `Basic realm="oauth21"`},
		"wrong client_secret":      {nil, url.Values{"client_id": {confidentialID}, "client_secret": {"wrong"}}, ""},
		"no authentication":        {nil, url.Values{"client_id": {confidentialID}}, ""},
		"no client":                {nil, nil, ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a := newConfidentialServer(t)
			params := a.confidentialCode()
			for k, v := range tt.form {
				params[k] = v
			}
			status, header, body := a.token(params, tt.header)
			wantStatus := http.StatusBadRequest
			if tt.challenge != "" {
				wantStatus = http.StatusUnauthorized
			}
			a.wantOAuthError(status, body, wantStatus, "invalid_client")
			if got := header.Get("WWW-Authenticate"); got != tt.challenge {
				t.Fatalf("got WWW-Authenticate %q, want %q", got, tt.challenge)
			}
		})
	}
}

// TestFailedClientAuthenticationKeepsCode checks that a request failing Client authentication does not use up the code.
func TestFailedClientAuthenticationKeepsCode(t *testing.T) {
	a := newConfidentialServer(t)
	params := a.confidentialCode()
	status, _, body := a.token(params, basic(confidentialID, "wrong"))
	a.wantOAuthError(status, body, http.StatusUnauthorized, "invalid_client")
	if status, _, body := a.token(params, basic(confidentialID, secret)); status != http.StatusOK {
		t.Fatalf("got status %d and body %v after a failed attempt, want 200", status, body)
	}
}

// TestMoreThanOneAuthenticationMethod checks that token, revocation and introspection requests using both client_secret_basic and client_secret_post get invalid_request, with and without client_id.
//
//conformance:covers INV-0005
func TestMoreThanOneAuthenticationMethod(t *testing.T) {
	a := newIntrospectionServer(t)
	_, refresh := a.tokens(a.confidentialCode(), basic(confidentialID, secret))
	for _, withID := range []bool{true, false} {
		for _, r := range []struct {
			path, id string
			params   url.Values
		}{
			{"/token", confidentialID, a.confidentialCode()},
			{"/revoke", confidentialID, url.Values{"token": {refresh}}},
			{"/introspect", resourceServerID, url.Values{"token": {refresh}}},
		} {
			if withID {
				r.params.Set("client_id", r.id)
			}
			r.params.Set("client_secret", secret)
			status, _, body := a.sendJSON(http.MethodPost, r.path, r.params.Encode(), basic(r.id, secret))
			a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
		}
	}
}

// TestRepeatedAuthorizationHeader checks that a request with more than one Authorization header gets invalid_request.
func TestRepeatedAuthorizationHeader(t *testing.T) {
	a := newConfidentialServer(t)
	header := basic(confidentialID, secret)
	header.Add("Authorization", "Bearer abc")
	status, _, body := a.token(a.confidentialCode(), header)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestPublicClientCannotUseBasic checks that a public Client presenting its own identifier with Basic gets invalid_client.
//
//conformance:covers OAUTH21D16-2.4.2-02
func TestPublicClientCannotUseBasic(t *testing.T) {
	a := newConfidentialServer(t)
	params := tokenParams(a.code(authorizeParams()))
	status, header, body := a.token(params, basic(clientID, ""))
	a.wantOAuthError(status, body, http.StatusUnauthorized, "invalid_client")
	if got := header.Get("WWW-Authenticate"); got != `Basic realm="oauth21"` {
		t.Fatalf("got WWW-Authenticate %q, want a Basic challenge", got)
	}
}

// TestCodeOfAnotherClient checks that a confidential Client cannot redeem a code issued to another Client.
//
//conformance:covers OAUTH21D16-4.1.3-08
func TestCodeOfAnotherClient(t *testing.T) {
	a := newConfidentialServer(t)
	params := tokenParams(a.code(authorizeParams()))
	params.Del("client_id")
	status, _, body := a.token(params, basic(confidentialID, secret))
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_grant")
}

// TestClientSecretPost checks that a confidential Client authenticates with client_id and client_secret in the request content.
//
//conformance:covers OAUTH21D16-2.4.1-01
func TestClientSecretPost(t *testing.T) {
	a := newConfidentialServer(t)
	params := a.confidentialCode()
	params.Set("client_id", confidentialID)
	params.Set("client_secret", secret)
	if status, _, body := a.token(params, nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v, want 200", status, body)
	}
}

// TestClientSecretBasic checks that a confidential Client authenticates with HTTP Basic.
//
//conformance:covers OAUTH21D16-2.4.1-05
func TestClientSecretBasic(t *testing.T) {
	a := newConfidentialServer(t)
	if status, _, body := a.token(a.confidentialCode(), basic(confidentialID, secret)); status != http.StatusOK {
		t.Fatalf("got status %d and body %v, want 200", status, body)
	}
}

// TestClientIDAloneDoesNotAuthenticate checks that a client credentials request carrying only the client_id of a confidential Client gets invalid_client.
//
//conformance:covers OAUTH21D16-2.2-01
func TestClientIDAloneDoesNotAuthenticate(t *testing.T) {
	a := newServiceServer(t)
	params := clientCredentialsParams("")
	params.Set("client_id", serviceID)
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
}

// TestClientSecretIsRequired checks that a confidential Client sending its client_id with an empty client_secret gets invalid_client.
//
//conformance:covers OAUTH21D16-2.4.1-03
func TestClientSecretIsRequired(t *testing.T) {
	a := newConfidentialServer(t)
	params := a.confidentialCode()
	params.Set("client_id", confidentialID)
	params.Set("client_secret", "")
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
}

// TestConfidentialClientMustAuthenticate checks that a confidential Client redeeming its code without credentials or with an empty Basic secret gets invalid_client.
//
//conformance:covers OAUTH21D16-3.2.2-04
func TestConfidentialClientMustAuthenticate(t *testing.T) {
	a := newConfidentialServer(t)
	params := a.confidentialCode()
	params.Set("client_id", confidentialID)
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
	status, _, body = a.token(a.confidentialCode(), basic(confidentialID, ""))
	a.wantOAuthError(status, body, http.StatusUnauthorized, "invalid_client")
}

// TestPublicRedemptionRequiresClientID checks that redeeming a public Client's code without client_id fails.
//
//conformance:covers OAUTH21D16-4.1.3-04
func TestPublicRedemptionRequiresClientID(t *testing.T) {
	a := newAuthorizationServer(t)
	params := tokenParams(a.code(authorizeParams()))
	params.Del("client_id")
	status, _, body := a.token(params, nil)
	a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
}

// TestRequestsFollowClientType checks that a public Client redeems its code without credentials while a confidential Client cannot, even one without a secret.
//
//conformance:covers OAUTH21D16-8.1.1-02
func TestRequestsFollowClientType(t *testing.T) {
	noSecret := confidentialClient(t)
	noSecret.ID, noSecret.SecretHash = "no secret", ""
	a := newAuthorizationServer(t, confidentialClient(t), noSecret)
	if status, _, body := a.token(tokenParams(a.code(authorizeParams())), nil); status != http.StatusOK {
		t.Fatalf("got status %d and body %v for the public Client, want 200", status, body)
	}
	for _, id := range []string{confidentialID, "no secret"} {
		params := authorizeParams()
		params.Set("client_id", id)
		token := tokenParams(a.code(params))
		token.Set("client_id", id)
		status, _, body := a.token(token, nil)
		a.wantOAuthError(status, body, http.StatusBadRequest, "invalid_client")
	}
}

// headerFailure is the status and the challenge scheme of a token response to failing Authorization header credentials.
type headerFailure struct {
	status int
	scheme string
}

// headerAuthenticationFailures sends a code redemption of the confidential Client with failing Basic and Bearer credentials and returns the response per scheme.
func (a *authorizationServer) headerAuthenticationFailures() map[string]headerFailure {
	a.t.Helper()
	got := map[string]headerFailure{}
	for scheme, header := range map[string]http.Header{
		"Basic":  basic(confidentialID, "wrong"),
		"Bearer": {"Authorization": {"Bearer abc"}},
	} {
		status, respHeader, body := a.token(a.confidentialCode(), header)
		if body["error"] != "invalid_client" {
			a.t.Fatalf("%s: got body %v, want invalid_client", scheme, body)
		}
		challenge, _, _ := strings.Cut(respHeader.Get("WWW-Authenticate"), " ")
		got[scheme] = headerFailure{status, challenge}
	}
	return got
}

// TestHeaderAuthenticationFailureIs401 checks that failed authentication with the Authorization header gets 401, for Basic and for another scheme.
//
//conformance:covers OAUTH21D16-3.2.4-03
func TestHeaderAuthenticationFailureIs401(t *testing.T) {
	a := newConfidentialServer(t)
	for scheme, got := range a.headerAuthenticationFailures() {
		if got.status != http.StatusUnauthorized {
			t.Fatalf("%s: got status %d, want 401", scheme, got.status)
		}
	}
}

// TestHeaderAuthenticationFailureChallengesScheme checks that failed authentication with the Authorization header gets a challenge with the scheme the Client used.
//
//conformance:covers OAUTH21D16-3.2.4-10
func TestHeaderAuthenticationFailureChallengesScheme(t *testing.T) {
	a := newConfidentialServer(t)
	for scheme, got := range a.headerAuthenticationFailures() {
		if got.scheme != scheme {
			t.Fatalf("got a %q challenge, want the %s scheme", got.scheme, scheme)
		}
	}
}
