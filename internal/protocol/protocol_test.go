package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
	"pgregory.net/rapid"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

var verifierGen = rapid.StringOfN(rapid.SampledFrom([]rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")), 43, 128, -1)

func TestVerifyPKCEKnownAnswer(t *testing.T) {
	// RFC 7636, Appendix B.
	if !verifyPKCE("S256", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") {
		t.Fatal("the RFC 7636 example does not verify")
	}
}

func TestVerifyPKCE(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := verifierGen.Draw(t, "verifier")
		other := rapid.String().Draw(t, "other")
		if !verifyPKCE("S256", s256(v), v) {
			t.Fatal("a verifier does not match its own challenge")
		}
		if other != v && verifyPKCE("S256", s256(v), other) {
			t.Fatal("another verifier matches")
		}
		if verifyPKCE("plain", v, v) {
			t.Fatal("plain verifies")
		}
	})
}

func TestVerifyPKCERejectsMalformedVerifier(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.String().Filter(func(s string) bool { return !pkceValue(s) }).Draw(t, "verifier")
		if verifyPKCE("S256", s256(v), v) {
			t.Fatalf("malformed verifier %q verifies", v)
		}
	})
}

var pathGen = rapid.StringMatching(`(/[a-z]{1,8}){0,3}`)

func TestMatchRedirectURIExact(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		host := rapid.StringMatching(`[a-z]{1,10}\.example`).Draw(t, "host")
		path := pathGen.Draw(t, "path")
		registered := "https://" + host + path
		if !matchRedirectURI([]string{registered}, registered) {
			t.Fatal("a registered redirect URI does not match itself")
		}
		other := pathGen.Draw(t, "other")
		port := rapid.IntRange(1, 65535).Draw(t, "port")
		if other != path && matchRedirectURI([]string{registered}, "https://"+host+other) {
			t.Fatal("another path matches")
		}
		if matchRedirectURI([]string{registered}, fmt.Sprintf("https://%s:%d%s", host, port, path)) {
			t.Fatal("a port matches a non-loopback redirect URI")
		}
	})
}

func TestMatchRedirectURILoopbackIgnoresPort(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		host := rapid.SampledFrom([]string{"127.0.0.1", "127.1.2.3", "[::1]"}).Draw(t, "host")
		path := pathGen.Draw(t, "path")
		registeredPort := rapid.SampledFrom([]string{"", ":8080"}).Draw(t, "registered port")
		port := rapid.IntRange(1, 65535).Draw(t, "port")
		registered := "http://" + host + registeredPort + path
		if !matchRedirectURI([]string{registered}, fmt.Sprintf("http://%s:%d%s", host, port, path)) {
			t.Fatal("a loopback redirect URI with another port does not match")
		}
		if other := pathGen.Draw(t, "other"); other != path && matchRedirectURI([]string{registered}, fmt.Sprintf("http://%s:%d%s", host, port, other)) {
			t.Fatal("a loopback redirect URI with another path matches")
		}
	})
}

func TestRedeemIssuedCode(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := verifierGen.Draw(t, "verifier")
		a := AuthorizationRequest{ClientID: "client", RedirectURI: "https://c.example/cb", CodeChallenge: s256(v), CodeChallengeMethod: "S256"}
		expiresAt := time.Unix(1_000_000, 0)
		code, err := IssueCode(a, "alice", nil, expiresAt)
		if err != nil {
			t.Fatal(err)
		}
		now := expiresAt.Add(time.Duration(rapid.Int64Range(-int64(time.Hour), int64(time.Hour)).Draw(t, "now")))
		clientID := rapid.SampledFrom([]string{"client", "other"}).Draw(t, "client")
		r := TokenRequest{
			GrantType:    "authorization_code",
			RedirectURI:  rapid.SampledFrom([]string{"", "https://c.example/cb", "https://c.example/other"}).Draw(t, "redirect_uri"),
			CodeVerifier: rapid.SampledFrom([]string{v, verifierGen.Draw(t, "other verifier")}).Draw(t, "code_verifier"),
		}
		code.Used = rapid.Bool().Draw(t, "used")
		bound := clientID == "client" && r.RedirectURI != "https://c.example/other" && r.CodeVerifier == v
		revoke, err := Redeem(&code, clientID, r, now)
		if want := bound && !code.Used && now.Before(expiresAt); (err == nil) != want {
			t.Fatalf("got redeemed %v, want %v", err == nil, want)
		}
		if revoke != (bound && code.Used) {
			t.Fatalf("got Grant revocation %v, want it for every replay with the right client and verifier", revoke)
		}
		if revoke, err := Redeem(nil, clientID, r, now); err == nil || revoke {
			t.Fatal("an unknown code redeems or revokes")
		}
	})
}

func TestAuthorize(t *testing.T) {
	client := &Client{ID: "client", Public: true, RedirectURIs: []string{"https://c.example/cb"}}
	two := &Client{ID: "client", Public: true, RedirectURIs: []string{"https://c.example/cb", "https://c.example/other"}}
	empty := &Client{ID: "client", Public: true, RedirectURIs: []string{""}}
	valid := AuthorizationParams{
		ResponseType:        "code",
		ClientID:            "client",
		State:               "s",
		CodeChallenge:       s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
		CodeChallengeMethod: "S256",
	}
	tests := map[string]struct {
		client     *Client
		change     func(*AuthorizationParams)
		code       string
		redirectTo string
	}{
		"valid":                         {client, func(*AuthorizationParams) {}, "", "https://c.example/cb"},
		"unknown client":                {nil, func(*AuthorizationParams) {}, "invalid_request", ""},
		"unregistered redirect_uri":     {client, func(r *AuthorizationParams) { r.RedirectURI = "https://evil.example/cb" }, "invalid_request", ""},
		"redirect_uri required":         {two, func(*AuthorizationParams) {}, "invalid_request", ""},
		"empty registered redirect_uri": {empty, func(*AuthorizationParams) {}, "invalid_request", ""},
		"chosen redirect_uri":           {two, func(r *AuthorizationParams) { r.RedirectURI = "https://c.example/other" }, "", "https://c.example/other"},
		"missing response_type":         {client, func(r *AuthorizationParams) { r.ResponseType = "" }, "invalid_request", "https://c.example/cb"},
		"token response_type":           {client, func(r *AuthorizationParams) { r.ResponseType = "token" }, "unsupported_response_type", "https://c.example/cb"},
		"missing code_challenge":        {client, func(r *AuthorizationParams) { r.CodeChallenge = "" }, "invalid_request", "https://c.example/cb"},
		"plain":                         {client, func(r *AuthorizationParams) { r.CodeChallengeMethod = "plain" }, "invalid_request", "https://c.example/cb"},
		"missing method":                {client, func(r *AuthorizationParams) { r.CodeChallengeMethod = "" }, "invalid_request", "https://c.example/cb"},
		"short code_challenge":          {client, func(r *AuthorizationParams) { r.CodeChallenge = "abc" }, "invalid_request", "https://c.example/cb"},
		"long code_challenge":           {client, func(r *AuthorizationParams) { r.CodeChallenge = strings.Repeat("a", 44) }, "invalid_request", "https://c.example/cb"},
		"non-base64url challenge":       {client, func(r *AuthorizationParams) { r.CodeChallenge = strings.Repeat("~", 43) }, "invalid_request", "https://c.example/cb"},
		"not a SHA-256 hash":            {client, func(r *AuthorizationParams) { r.CodeChallenge = strings.Repeat("A", 42) + "B" }, "invalid_request", "https://c.example/cb"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := valid
			tt.change(&r)
			expiresAt := time.Unix(1_000_000, 0)
			a, err := Authorize(tt.client, r, expiresAt)
			if code := errorCode(err); code != tt.code || a.RedirectURI != tt.redirectTo {
				t.Fatalf("got error %q and redirect URI %q, want %q and %q", code, a.RedirectURI, tt.code, tt.redirectTo)
			}
			if err == nil && !a.ExpiresAt.Equal(expiresAt) {
				t.Fatalf("got ExpiresAt %v, want %v", a.ExpiresAt, expiresAt)
			}
		})
	}
}

// verify accepts the secret "secret" for the hash "hash".
func verify(hash, secret string) bool {
	return hash == "hash" && secret == "secret"
}

func TestValidateTokenRequest(t *testing.T) {
	public := &Client{ID: "client", Public: true}
	valid := TokenRequest{GrantType: "authorization_code", Code: "c", ClientID: "client", CodeVerifier: "v"}
	tests := map[string]struct {
		client *Client
		change func(*TokenRequest)
		code   string
	}{
		"valid":              {public, func(*TokenRequest) {}, ""},
		"missing grant_type": {public, func(r *TokenRequest) { r.GrantType = "" }, "invalid_request"},
		"other grant_type":   {public, func(r *TokenRequest) { r.GrantType = "password" }, "unsupported_grant_type"},
		"missing code":       {public, func(r *TokenRequest) { r.Code = "" }, "invalid_request"},
		"missing verifier":   {public, func(r *TokenRequest) { r.CodeVerifier = "" }, "invalid_request"},
		"unauthenticated":    {nil, func(*TokenRequest) {}, "invalid_client"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := valid
			tt.change(&r)
			if code := errorCode(ValidateTokenRequest(tt.client, r, verify)); code != tt.code {
				t.Fatalf("got error %q, want %q", code, tt.code)
			}
		})
	}
}

func TestIdentify(t *testing.T) {
	tests := map[string]struct {
		r    TokenRequest
		id   string
		code string
	}{
		"client_id":                  {TokenRequest{ClientID: "c"}, "c", ""},
		"client_secret_post":         {TokenRequest{ClientID: "c", ClientSecret: "s"}, "c", ""},
		"client_secret_basic":        {TokenRequest{AuthScheme: "Basic", BasicID: "c"}, "c", ""},
		"Basic with client_id":       {TokenRequest{ClientID: "c", AuthScheme: "Basic", BasicID: "c"}, "c", ""},
		"other scheme":               {TokenRequest{ClientID: "c", AuthScheme: "Bearer"}, "c", ""},
		"none":                       {TokenRequest{}, "", ""},
		"Basic and client_secret":    {TokenRequest{ClientSecret: "s", AuthScheme: "Basic", BasicID: "c"}, "", "invalid_request"},
		"scheme and client_secret":   {TokenRequest{ClientID: "c", ClientSecret: "s", AuthScheme: "Bearer"}, "", "invalid_request"},
		"Basic with other client_id": {TokenRequest{ClientID: "d", AuthScheme: "Basic", BasicID: "c"}, "", "invalid_client"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			id, err := Identify(tt.r)
			if id != tt.id || errorCode(err) != tt.code {
				t.Fatalf("got %q and error %v, want %q and %q", id, err, tt.id, tt.code)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	public := &Client{ID: "client", Public: true}
	confidential := &Client{ID: "client", SecretHash: "hash"}
	tests := map[string]struct {
		client *Client
		r      TokenRequest
		ok     bool
	}{
		"public":                        {public, TokenRequest{ClientID: "client"}, true},
		"client_secret_basic":           {confidential, TokenRequest{AuthScheme: "Basic", BasicID: "client", BasicSecret: "secret"}, true},
		"client_secret_post":            {confidential, TokenRequest{ClientID: "client", ClientSecret: "secret"}, true},
		"unknown client":                {nil, TokenRequest{ClientID: "client"}, false},
		"public with client_secret":     {public, TokenRequest{ClientID: "client", ClientSecret: "secret"}, false},
		"public with Basic":             {public, TokenRequest{AuthScheme: "Basic", BasicID: "client"}, false},
		"public with other scheme":      {public, TokenRequest{ClientID: "client", AuthScheme: "Bearer"}, false},
		"confidential without a secret": {confidential, TokenRequest{ClientID: "client"}, false},
		"wrong Basic secret":            {confidential, TokenRequest{AuthScheme: "Basic", BasicID: "client", BasicSecret: "wrong"}, false},
		"wrong client_secret":           {confidential, TokenRequest{ClientID: "client", ClientSecret: "wrong"}, false},
		"empty Basic secret":            {confidential, TokenRequest{AuthScheme: "Basic", BasicID: "client"}, false},
		"other scheme":                  {confidential, TokenRequest{ClientID: "client", AuthScheme: "Bearer"}, false},
		"no secret hash":                {&Client{ID: "client"}, TokenRequest{ClientID: "client", ClientSecret: "secret"}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := Authenticate(tt.client, tt.r, verify)
			if (err == nil) != tt.ok || err != nil && err.Code != "invalid_client" {
				t.Fatalf("got error %v, want authenticated %v or invalid_client", err, tt.ok)
			}
		})
	}
}

func TestIssueCodeBindsRequest(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := AuthorizationRequest{
			ClientID:            rapid.String().Draw(t, "client"),
			RedirectURI:         rapid.String().Draw(t, "redirect_uri"),
			CodeChallenge:       rapid.String().Draw(t, "code_challenge"),
			CodeChallengeMethod: rapid.String().Draw(t, "method"),
		}
		subject := rapid.StringN(1, -1, -1).Draw(t, "subject")
		scopes := rapid.SliceOf(rapid.String()).Draw(t, "scopes")
		expiresAt := time.Unix(rapid.Int64Range(0, 1<<40).Draw(t, "expires_at"), 0)
		code, err := IssueCode(a, subject, scopes, expiresAt)
		if err != nil {
			t.Fatal(err)
		}
		want := Code{a.ClientID, subject, scopes, a.RedirectURI, a.CodeChallenge, a.CodeChallengeMethod, expiresAt, false}
		if !reflect.DeepEqual(code, want) {
			t.Fatalf("got %+v, want %+v", code, want)
		}
	})
}

func TestIssueCodeRejectsEmptyGrant(t *testing.T) {
	if _, err := IssueCode(AuthorizationRequest{Scopes: []string{"read"}}, "alice", nil, time.Time{}); err == nil {
		t.Fatal("got a code granting no scopes for a request with scopes")
	}
	if _, err := IssueCode(AuthorizationRequest{}, "alice", nil, time.Time{}); err != nil {
		t.Fatalf("got error %v for a request without scopes", err)
	}
}

func TestTokenCreated(t *testing.T) {
	if err := TokenCreated(false); err != nil {
		t.Fatalf("got error %v for a created token", err)
	}
	if err := TokenCreated(true); errorCode(err) != "invalid_grant" {
		t.Fatalf("got error %v for a revoked Grant, want invalid_grant", err)
	}
}

func TestIssueCodeRequiresSubject(t *testing.T) {
	if _, err := IssueCode(AuthorizationRequest{ClientID: "client"}, "", nil, time.Time{}); err == nil {
		t.Fatal("got a code without a subject")
	}
}

func errorCode(err *Error) string {
	if err == nil {
		return ""
	}
	return err.Code
}

func TestPending(t *testing.T) {
	expiresAt := time.Unix(1_000_000, 0)
	tests := map[string]struct {
		request *AuthorizationRequest
		now     time.Time
		pending bool
	}{
		"pending":     {&AuthorizationRequest{ExpiresAt: expiresAt}, expiresAt.Add(-time.Nanosecond), true},
		"at expiry":   {&AuthorizationRequest{ExpiresAt: expiresAt}, expiresAt, false},
		"expired":     {&AuthorizationRequest{ExpiresAt: expiresAt}, expiresAt.Add(time.Hour), false},
		"unknown":     {nil, expiresAt.Add(-time.Hour), false},
		"zero expiry": {&AuthorizationRequest{}, expiresAt, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if err := Pending(tt.request, tt.now); (err == nil) != tt.pending {
				t.Fatalf("got error %v, want pending %v", err, tt.pending)
			}
		})
	}
}

func TestDenied(t *testing.T) {
	if code := errorCode(Denied()); code != "access_denied" {
		t.Fatalf("got error %q, want access_denied", code)
	}
}
