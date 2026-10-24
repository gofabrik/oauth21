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
	hash, err := oauth21.PBKDF2{Iterations: 1000}.Hash(secret)
	if err != nil {
		t.Fatal(err)
	}
	return newAuthorizationServer(t, store.Client{ID: confidentialID, Type: store.Confidential, RedirectURIs: []string{redirectURI}, AllowedScopes: readScope, DefaultScopes: readScope, SecretHash: hash})
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

// TestConfidentialClientAuthenticates checks that a confidential Client redeems a code with client_secret_basic or client_secret_post.
func TestConfidentialClientAuthenticates(t *testing.T) {
	t.Run("client_secret_basic", func(t *testing.T) {
		a := newConfidentialServer(t)
		status, _, body := a.token(a.confidentialCode(), basic(confidentialID, secret))
		if status != http.StatusOK {
			t.Fatalf("got status %d and body %v, want 200", status, body)
		}
	})
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
	t.Run("client_secret_post", func(t *testing.T) {
		a := newConfidentialServer(t)
		params := a.confidentialCode()
		params.Set("client_id", confidentialID)
		params.Set("client_secret", secret)
		status, _, body := a.token(params, nil)
		if status != http.StatusOK {
			t.Fatalf("got status %d and body %v, want 200", status, body)
		}
	})
}

// TestFailedClientAuthentication checks that failed authentication gets invalid_client, as a 401 with a Basic challenge when the Authorization header was used.
func TestFailedClientAuthentication(t *testing.T) {
	tests := map[string]struct {
		header    http.Header
		form      url.Values
		challenge string
	}{
		"wrong Basic secret":     {basic(confidentialID, "wrong"), nil, `Basic realm="oauth21"`},
		"unencoded Basic secret": {basic(confidentialID, url.QueryEscape(secret)), nil, `Basic realm="oauth21"`},
		"unknown Basic client":   {basic("unknown", secret), nil, `Basic realm="oauth21"`},
		"malformed Basic":        {http.Header{"Authorization": {"Basic !"}}, nil, `Basic realm="oauth21"`},
		"wrong client_secret":    {nil, url.Values{"client_id": {confidentialID}, "client_secret": {"wrong"}}, ""},
		"no authentication":      {nil, url.Values{"client_id": {confidentialID}}, ""},
		"no client":              {nil, nil, ""},
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
			a.wantTokenError(status, body, wantStatus, "invalid_client")
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
	a.wantTokenError(status, body, http.StatusUnauthorized, "invalid_client")
	if status, _, body := a.token(params, basic(confidentialID, secret)); status != http.StatusOK {
		t.Fatalf("got status %d and body %v after a failed attempt, want 200", status, body)
	}
}

// TestMoreThanOneAuthenticationMethod checks that a request using both client_secret_basic and client_secret_post gets invalid_request.
func TestMoreThanOneAuthenticationMethod(t *testing.T) {
	a := newConfidentialServer(t)
	params := a.confidentialCode()
	params.Set("client_secret", secret)
	status, _, body := a.token(params, basic(confidentialID, secret))
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestRepeatedAuthorizationHeader checks that a request with more than one Authorization header gets invalid_request.
func TestRepeatedAuthorizationHeader(t *testing.T) {
	a := newConfidentialServer(t)
	header := basic(confidentialID, secret)
	header.Add("Authorization", "Bearer abc")
	status, _, body := a.token(a.confidentialCode(), header)
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_request")
}

// TestPublicClientCannotUseBasic checks that a public Client presenting its own identifier with Basic gets invalid_client.
func TestPublicClientCannotUseBasic(t *testing.T) {
	a := newConfidentialServer(t)
	params := tokenParams(a.code(authorizeParams()))
	status, header, body := a.token(params, basic(clientID, ""))
	a.wantTokenError(status, body, http.StatusUnauthorized, "invalid_client")
	if got := header.Get("WWW-Authenticate"); got != `Basic realm="oauth21"` {
		t.Fatalf("got WWW-Authenticate %q, want a Basic challenge", got)
	}
}

// TestCodeOfAnotherClient checks that a confidential Client cannot redeem a code issued to another Client.
func TestCodeOfAnotherClient(t *testing.T) {
	a := newConfidentialServer(t)
	params := tokenParams(a.code(authorizeParams()))
	params.Del("client_id")
	status, _, body := a.token(params, basic(confidentialID, secret))
	a.wantTokenError(status, body, http.StatusBadRequest, "invalid_grant")
}
