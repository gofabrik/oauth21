package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"slices"
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
		a := AuthorizationRequest{ClientID: "client", RedirectURI: "https://c.example/cb", Scopes: []string{"read"}, CodeChallenge: s256(v), CodeChallengeMethod: "S256"}
		expiresAt := time.Unix(1_000_000, 0)
		code, err := IssueCode(a, "alice", a.Scopes, expiresAt, time.Hour)
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
		effect, err := Redeem(&code, clientID, r, now)
		if want := bound && !code.Used && now.Before(expiresAt); (effect == ConsumeCode) != want || (err == nil) != want {
			t.Fatalf("got effect %v and error %v, want consume %v", effect, err, want)
		}
		if (effect == RevokeGrant) != (bound && code.Used) {
			t.Fatalf("got effect %v, want Grant revocation for every replay with the right client and verifier", effect)
		}
		if effect, err := Redeem(nil, clientID, r, now); err == nil || effect != NoEffect {
			t.Fatal("an unknown code redeems or revokes")
		}
	})
}

// TestRedemption checks the two-step redemption of a code against a model, including redemptions that race for the consume and a clock that moves during it.
func TestRedemption(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := verifierGen.Draw(t, "verifier")
		expiresAt := time.Unix(1_000_000, 0)
		now := expiresAt.Add(-time.Minute)
		stored, perr := IssueCode(AuthorizationRequest{ClientID: "client", Scopes: []string{"read"}, CodeChallenge: s256(v), CodeChallengeMethod: "S256"}, "alice", []string{"read"}, expiresAt, time.Hour)
		if perr != nil {
			t.Fatal(perr)
		}
		consumed, issued := false, 0
		// redeem redeems from snapshot, the code as read before the consume, and checks the outcome against the model.
		redeem := func(t *rapid.T, snapshot Code) {
			verifier := v
			if !rapid.Bool().Draw(t, "right verifier") {
				verifier = strings.Repeat("w", 43)
			}
			consumedAt := now.Add(time.Duration(rapid.Int64Range(0, int64(time.Second)).Draw(t, "consume duration")))
			wantConsume := verifier == v && !consumed && now.Before(expiresAt)
			wantIssue := wantConsume && consumedAt.Before(expiresAt)
			wantRevoke := verifier == v && consumed
			effect, err := Redeem(&snapshot, "client", TokenRequest{CodeVerifier: verifier}, now)
			if effect == ConsumeCode {
				before := stored
				stored.Used = true
				effect, err = Consumed(&before, consumedAt)
			}
			if (err == nil) != wantIssue || (effect == RevokeGrant) != wantRevoke {
				t.Fatalf("got effect %v and error %v, want issue %v and Grant revocation %v", effect, err, wantIssue, wantRevoke)
			}
			consumed = consumed || wantConsume
			if wantIssue {
				issued++
			}
		}
		t.Repeat(map[string]func(*rapid.T){
			"advance": func(t *rapid.T) {
				now = now.Add(time.Duration(rapid.Int64Range(0, int64(30*time.Second)).Draw(t, "advance")))
			},
			"redeem": func(t *rapid.T) {
				redeem(t, stored)
			},
			"redeem twice from one read": func(t *rapid.T) {
				snapshot := stored
				redeem(t, snapshot)
				redeem(t, snapshot)
			},
			"": func(t *rapid.T) {
				if issued > 1 {
					t.Fatalf("issued tokens %d times for one code", issued)
				}
			},
		})
		if effect, err := Consumed(nil, now); err == nil || effect != NoEffect {
			t.Fatal("consuming an unknown code redeems or revokes")
		}
	})
}

var supportedScopes = []string{"read", "write", "admin"}

func TestAuthorize(t *testing.T) {
	scopes := []string{"read", "write"}
	client := &Client{ID: "client", Public: true, RedirectURIs: []string{"https://c.example/cb"}, AllowedScopes: scopes, DefaultScopes: scopes[:1]}
	two := &Client{ID: "client", Public: true, RedirectURIs: []string{"https://c.example/cb", "https://c.example/other"}, AllowedScopes: scopes, DefaultScopes: scopes[:1]}
	empty := &Client{ID: "client", Public: true, RedirectURIs: []string{""}, AllowedScopes: scopes, DefaultScopes: scopes[:1]}
	noDefaults := &Client{ID: "client", Public: true, RedirectURIs: []string{"https://c.example/cb"}, AllowedScopes: scopes}
	noCode := &Client{ID: "client", RedirectURIs: []string{"https://c.example/cb"}, AllowedScopes: scopes, DefaultScopes: scopes[:1], GrantTypes: []string{"client_credentials"}}
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
		"valid":                          {client, func(*AuthorizationParams) {}, "", "https://c.example/cb"},
		"unknown client":                 {nil, func(*AuthorizationParams) {}, "invalid_request", ""},
		"unregistered redirect_uri":      {client, func(r *AuthorizationParams) { r.RedirectURI = "https://evil.example/cb" }, "invalid_request", ""},
		"redirect_uri required":          {two, func(*AuthorizationParams) {}, "invalid_request", ""},
		"empty registered redirect_uri":  {empty, func(*AuthorizationParams) {}, "invalid_request", ""},
		"chosen redirect_uri":            {two, func(r *AuthorizationParams) { r.RedirectURI = "https://c.example/other" }, "", "https://c.example/other"},
		"missing response_type":          {client, func(r *AuthorizationParams) { r.ResponseType = "" }, "invalid_request", "https://c.example/cb"},
		"token response_type":            {client, func(r *AuthorizationParams) { r.ResponseType = "token" }, "unsupported_response_type", "https://c.example/cb"},
		"missing code_challenge":         {client, func(r *AuthorizationParams) { r.CodeChallenge = "" }, "invalid_request", "https://c.example/cb"},
		"plain":                          {client, func(r *AuthorizationParams) { r.CodeChallengeMethod = "plain" }, "invalid_request", "https://c.example/cb"},
		"missing method":                 {client, func(r *AuthorizationParams) { r.CodeChallengeMethod = "" }, "invalid_request", "https://c.example/cb"},
		"short code_challenge":           {client, func(r *AuthorizationParams) { r.CodeChallenge = "abc" }, "invalid_request", "https://c.example/cb"},
		"long code_challenge":            {client, func(r *AuthorizationParams) { r.CodeChallenge = strings.Repeat("a", 44) }, "invalid_request", "https://c.example/cb"},
		"non-base64url challenge":        {client, func(r *AuthorizationParams) { r.CodeChallenge = strings.Repeat("~", 43) }, "invalid_request", "https://c.example/cb"},
		"not a SHA-256 hash":             {client, func(r *AuthorizationParams) { r.CodeChallenge = strings.Repeat("A", 42) + "B" }, "invalid_request", "https://c.example/cb"},
		"allowed scope":                  {client, func(r *AuthorizationParams) { r.Scope = "write read" }, "", "https://c.example/cb"},
		"no default scopes":              {noDefaults, func(*AuthorizationParams) {}, "invalid_scope", "https://c.example/cb"},
		"unsupported scope":              {client, func(r *AuthorizationParams) { r.Scope = "read delete" }, "invalid_scope", "https://c.example/cb"},
		"scope not allowed":              {client, func(r *AuthorizationParams) { r.Scope = "read admin" }, "invalid_scope", "https://c.example/cb"},
		"tab-separated scopes":           {client, func(r *AuthorizationParams) { r.Scope = "read\twrite" }, "invalid_scope", "https://c.example/cb"},
		"authorization_code not allowed": {noCode, func(*AuthorizationParams) {}, "unauthorized_client", "https://c.example/cb"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := valid
			tt.change(&r)
			expiresAt := time.Unix(1_000_000, 0)
			a, err := Authorize(tt.client, r, supportedScopes, expiresAt)
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
	serviceOnly := &Client{ID: "client", SecretHash: "hash", GrantTypes: []string{"client_credentials"}}
	noRefresh := &Client{ID: "client", Public: true, GrantTypes: []string{"authorization_code"}}
	valid := TokenRequest{GrantType: "authorization_code", Code: "c", ClientID: "client", CodeVerifier: "v"}
	clientCredentials := TokenRequest{GrantType: "client_credentials", ClientID: "client", ClientSecret: "secret"}
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
		"refresh": {public, func(r *TokenRequest) {
			*r = TokenRequest{GrantType: "refresh_token", RefreshToken: "r", ClientID: "client"}
		}, ""},
		"missing refresh":         {public, func(r *TokenRequest) { *r = TokenRequest{GrantType: "refresh_token", ClientID: "client"} }, "invalid_request"},
		"refresh unauthenticated": {nil, func(r *TokenRequest) { *r = TokenRequest{GrantType: "refresh_token", RefreshToken: "r"} }, "invalid_client"},
		"unauthenticated":         {nil, func(*TokenRequest) {}, "invalid_client"},
		"refresh not allowed": {noRefresh, func(r *TokenRequest) {
			*r = TokenRequest{GrantType: "refresh_token", RefreshToken: "r", ClientID: "client"}
		}, "unauthorized_client"},
		"code not allowed":                      {serviceOnly, func(r *TokenRequest) { r.ClientSecret = "secret" }, "unauthorized_client"},
		"client_credentials":                    {serviceOnly, func(r *TokenRequest) { *r = clientCredentials }, ""},
		"client_credentials not allowed":        {&Client{ID: "client", SecretHash: "hash"}, func(r *TokenRequest) { *r = clientCredentials }, "unauthorized_client"},
		"client_credentials unauthenticated":    {serviceOnly, func(r *TokenRequest) { *r = clientCredentials; r.ClientSecret = "wrong" }, "invalid_client"},
		"client_credentials for unknown client": {nil, func(r *TokenRequest) { *r = clientCredentials }, "invalid_client"},
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
		a.Scopes = rapid.SliceOfNDistinct(rapid.String(), 1, -1, rapid.ID).Draw(t, "scopes")
		subject := rapid.StringN(1, -1, -1).Draw(t, "subject")
		expiresAt := time.Unix(rapid.Int64Range(0, 1<<40).Draw(t, "expires_at"), 0)
		code, err := IssueCode(a, subject, a.Scopes, expiresAt, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		want := Code{a.ClientID, subject, a.Scopes, a.RedirectURI, a.CodeChallenge, a.CodeChallengeMethod, expiresAt, expiresAt.Add(time.Hour), false}
		if !reflect.DeepEqual(code, want) {
			t.Fatalf("got %+v, want %+v", code, want)
		}
	})
}

func TestTokenExpiry(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	limit := now.Add(90 * time.Minute)
	for lifetime, want := range map[time.Duration]time.Time{
		time.Minute:   now.Add(time.Minute),
		time.Hour:     now.Add(time.Hour),
		2 * time.Hour: limit,
	} {
		if got := TokenExpiry(now, lifetime, limit); !got.Equal(want) {
			t.Errorf("got expiry %v for lifetime %v, want %v", got, lifetime, want)
		}
	}
}

func TestConsumedRejectsCodePastRetention(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	code := Code{ExpiresAt: now.Add(time.Minute)}
	if effect, err := Consumed(&code, now); err == nil || effect != NoEffect {
		t.Fatalf("got effect %v and error %v for a code without RetainUntil, want it rejected", effect, err)
	}
}

func TestIssueCodeGrantsRequestedScopes(t *testing.T) {
	a := AuthorizationRequest{Scopes: []string{"read", "write"}}
	for name, tt := range map[string]struct {
		granted []string
		want    []string
	}{
		"all":           {[]string{"write", "read"}, []string{"read", "write"}},
		"fewer":         {[]string{"write"}, []string{"write"}},
		"repeated":      {[]string{"read", "read"}, []string{"read"}},
		"none":          {nil, nil},
		"not requested": {[]string{"read", "admin"}, nil},
	} {
		code, err := IssueCode(a, "alice", tt.granted, time.Time{}, time.Hour)
		if (err == nil) != (tt.want != nil) || !slices.Equal(code.Scopes, tt.want) {
			t.Errorf("%s: got scopes %q and error %v, want %q", name, code.Scopes, err, tt.want)
		}
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
	if _, err := IssueCode(AuthorizationRequest{ClientID: "client"}, "", nil, time.Time{}, time.Hour); err == nil {
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

func TestAuthorizeResolvesScopes(t *testing.T) {
	client := &Client{ID: "client", RedirectURIs: []string{"https://c.example/cb"}, AllowedScopes: supportedScopes, DefaultScopes: []string{"read", "write"}}
	for requested, want := range map[string][]string{
		"":                 {"read", "write"},
		"admin":            {"admin"},
		"write read write": {"write", "read"},
		"read  write ":     {"read", "write"},
	} {
		r := AuthorizationParams{ResponseType: "code", Scope: requested, CodeChallenge: s256(verifierGen.Example()), CodeChallengeMethod: "S256"}
		a, err := Authorize(client, r, supportedScopes, time.Time{})
		if err != nil || !slices.Equal(a.Scopes, want) {
			t.Errorf("got scopes %q and error %v for scope %q, want %q", a.Scopes, err, requested, want)
		}
	}
}

// malformedScopes are not scope-tokens.
var malformedScopes = []string{"read write", "a\tb", `x"y`, `x\y`, "é", "\x7f"}

var scopeGen = rapid.SampledFrom(append([]string{"", "read", "write", "admin", "openid"}, malformedScopes...))

// TestScopesStayWithinLimits checks that a Client gets only scopes that are supported, allowed for it, requested or default, and granted.
func TestScopesStayWithinLimits(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		supported := rapid.SliceOf(scopeGen).Draw(t, "supported")
		client := &Client{
			ID:            "client",
			RedirectURIs:  []string{"https://c.example/cb"},
			AllowedScopes: rapid.SliceOf(scopeGen).Draw(t, "allowed"),
			DefaultScopes: rapid.SliceOf(scopeGen).Draw(t, "defaults"),
		}
		requested := rapid.SliceOf(scopeGen).Draw(t, "requested")
		r := AuthorizationParams{ResponseType: "code", Scope: strings.Join(requested, " "), CodeChallenge: s256(verifierGen.Draw(t, "verifier")), CodeChallengeMethod: "S256"}
		asked := strings.Split(r.Scope, " ")
		if r.Scope == "" {
			asked = client.DefaultScopes
		}
		asked = slices.DeleteFunc(slices.Clone(asked), func(s string) bool { return s == "" })
		valid := len(asked) > 0 && !slices.ContainsFunc(asked, func(s string) bool {
			return slices.Contains(malformedScopes, s) || !slices.Contains(supported, s) || !slices.Contains(client.AllowedScopes, s)
		})
		a, err := Authorize(client, r, supported, time.Time{})
		if (err == nil) != valid || err != nil && err.Code != "invalid_scope" {
			t.Fatalf("got scopes %q and error %v, want valid %v", a.Scopes, err, valid)
		}
		if err != nil {
			return
		}
		if !distinct(a.Scopes) {
			t.Fatalf("got repeated scopes %q", a.Scopes)
		}
		for _, s := range a.Scopes {
			if !slices.Contains(asked, s) || !slices.Contains(supported, s) || !slices.Contains(client.AllowedScopes, s) {
				t.Fatalf("got scope %q of %q for %q", s, a.Scopes, asked)
			}
		}
		granted := rapid.SliceOf(scopeGen).Draw(t, "granted")
		code, err := IssueCode(a, "alice", granted, time.Time{}, time.Hour)
		want := len(granted) > 0 && !slices.ContainsFunc(granted, func(s string) bool { return !slices.Contains(a.Scopes, s) })
		if (err == nil) != want {
			t.Fatalf("got error %v granting %q of %q, want a code %v", err, granted, a.Scopes, want)
		}
		if !distinct(code.Scopes) {
			t.Fatalf("got repeated code scopes %q", code.Scopes)
		}
		for _, s := range code.Scopes {
			if !slices.Contains(granted, s) || !slices.Contains(a.Scopes, s) {
				t.Fatalf("got code scopes %q granting %q of %q", code.Scopes, granted, a.Scopes)
			}
		}
	})
}

func distinct(s []string) bool {
	return len(slices.Compact(slices.Sorted(slices.Values(s)))) == len(s)
}

func TestResolveScopesHidesSupportedScopes(t *testing.T) {
	_, unsupported := resolveScopes("delete", supportedScopes, []string{"read"}, nil)
	_, notAllowed := resolveScopes("admin", supportedScopes, []string{"read"}, nil)
	if unsupported == nil || notAllowed == nil || *unsupported != *notAllowed {
		t.Fatalf("got errors %v and %v, want the same error for an unsupported and a disallowed scope", unsupported, notAllowed)
	}
}

func TestResolveScopesRejectsMalformedScopes(t *testing.T) {
	for _, scope := range malformedScopes {
		configured := []string{scope}
		for _, requested := range []string{"", scope} {
			if scopes, err := resolveScopes(requested, configured, configured, configured); errorCode(err) != "invalid_scope" {
				t.Errorf("got scopes %q and error %v for %q requesting %q, want invalid_scope", scopes, err, scope, requested)
			}
		}
	}
}

// wellFormed reports whether s is one or more of the characters a scope-token allows (RFC 6749, Appendix A.4).
func wellFormed(s string) bool {
	return s != "" && strings.IndexFunc(s, func(c rune) bool { return c < 0x21 || c > 0x7e || c == '"' || c == '\\' }) < 0
}

func FuzzResolveScopes(f *testing.F) {
	f.Add("read write", "admin")
	f.Add("", "read write")
	f.Add("read  admin", "")
	f.Add("read\twrite", "a\tb")
	f.Fuzz(func(t *testing.T, requested, scope string) {
		allowed := []string{"read", "write", scope}
		scopes, err := resolveScopes(requested, append(supportedScopes, scope), allowed, []string{scope})
		if err != nil && err.Code != "invalid_scope" || err == nil && len(scopes) == 0 {
			t.Fatalf("got scopes %q and error %v", scopes, err)
		}
		for _, s := range scopes {
			if !slices.Contains(allowed, s) || !wellFormed(s) {
				t.Fatalf("got scope %q for %q", s, requested)
			}
		}
	})
}

func TestScopeToken(t *testing.T) {
	for _, s := range []string{"read", "a:b", "!#[]~"} {
		if !ScopeToken(s) {
			t.Errorf("%q is not a scope-token", s)
		}
	}
	for _, s := range append([]string{""}, malformedScopes...) {
		if ScopeToken(s) {
			t.Errorf("%q is a scope-token", s)
		}
	}
}

func TestRefresh(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		expiresAt := time.Unix(1_000_000, 0)
		token := RefreshToken{ClientID: "client", Scopes: []string{"read", "write"}, ExpiresAt: expiresAt, Rotated: rapid.Bool().Draw(t, "rotated")}
		client := Client{ID: rapid.SampledFrom([]string{"client", "other"}).Draw(t, "client"), Public: rapid.Bool().Draw(t, "public"), AllowedScopes: supportedScopes}
		requested := rapid.SampledFrom([]string{"", "read", "write read", "admin", "read admin"}).Draw(t, "scope")
		reuseConfidential := rapid.Bool().Draw(t, "reuse confidential")
		now := expiresAt.Add(time.Duration(rapid.Int64Range(-int64(time.Hour), int64(time.Hour)).Draw(t, "now")))
		effect, scopes, err := Refresh(&token, client, TokenRequest{Scope: requested}, supportedScopes, reuseConfidential, now)
		bound := client.ID == "client"
		granted := !strings.Contains(requested, "admin")
		want := bound && !token.Rotated && now.Before(expiresAt) && granted
		if (err == nil) != want {
			t.Fatalf("got error %v, want a refresh %v", err, want)
		}
		if (effect == RevokeGrant) != (bound && token.Rotated) {
			t.Fatalf("got effect %v, want Grant revocation for every rotated token presented by its Client", effect)
		}
		if want && (effect == RotateRefreshToken) != (client.Public || !reuseConfidential) {
			t.Fatalf("got effect %v, want rotation unless a confidential Client reuses its token", effect)
		}
		for _, s := range scopes {
			if !slices.Contains(token.Scopes, s) || requested != "" && !strings.Contains(requested, s) {
				t.Fatalf("got scopes %q for %q of %q", scopes, requested, token.Scopes)
			}
		}
		if want && requested == "" && !slices.Equal(scopes, token.Scopes) {
			t.Fatalf("got scopes %q without scope, want the granted %q", scopes, token.Scopes)
		}
		if effect, _, err := Refresh(nil, client, TokenRequest{}, supportedScopes, reuseConfidential, now); err == nil || effect != NoEffect {
			t.Fatal("an unknown refresh token refreshes or revokes")
		}
	})
}

func TestRefreshKeepsScopesWithinLimits(t *testing.T) {
	token := RefreshToken{ClientID: "client", Scopes: []string{"read", "write"}, ExpiresAt: time.Unix(1_000_000, 0)}
	client := Client{ID: "client", Public: true, AllowedScopes: []string{"read", "write"}}
	now := token.ExpiresAt.Add(-time.Minute)
	for name, tt := range map[string]struct {
		requested string
		supported []string
		allowed   []string
		want      []string
	}{
		"omitted":             {"", supportedScopes, client.AllowedScopes, []string{"read", "write"}},
		"narrower":            {"write", supportedScopes, client.AllowedScopes, []string{"write"}},
		"not granted":         {"read admin", supportedScopes, supportedScopes, nil},
		"no longer allowed":   {"", supportedScopes, []string{"read"}, []string{"read"}},
		"no longer supported": {"write", []string{"read"}, client.AllowedScopes, nil},
		"none left":           {"", supportedScopes, []string{"admin"}, nil},
	} {
		c := client
		c.AllowedScopes = tt.allowed
		_, scopes, err := Refresh(&token, c, TokenRequest{Scope: tt.requested}, tt.supported, false, now)
		if (err == nil) != (tt.want != nil) || err != nil && err.Code != "invalid_scope" || !slices.Equal(scopes, tt.want) {
			t.Errorf("%s: got scopes %q and error %v, want %q", name, scopes, err, tt.want)
		}
	}
}

// TestRefreshTokenFamily checks the refresh tokens of one Grant against a model, including refreshes that race for the rotation, a clock that moves during it, and Grant revocation.
func TestRefreshTokenFamily(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		expiresAt := time.Unix(1_000_000, 0)
		now := expiresAt.Add(-time.Hour)
		client := Client{ID: "client", Public: rapid.Bool().Draw(t, "public"), AllowedScopes: []string{"read"}}
		reuseConfidential := rapid.Bool().Draw(t, "reuse confidential")
		rotates := client.Public || !reuseConfidential
		code := Code{ClientID: "client", Scopes: []string{"read"}, RetainUntil: expiresAt.Add(time.Hour)}
		stored := []RefreshToken{*IssueRefreshToken(Client{ID: code.ClientID}, code, now, time.Hour)}
		revoked, current, issued := false, 0, map[int]int{}
		load := func(i int) *RefreshToken {
			if revoked {
				return nil
			}
			token := stored[i]
			return &token
		}
		// refresh refreshes with token i from snapshot, the token as read before the rotation, and checks the outcome against the model.
		refresh := func(t *rapid.T, i int, snapshot *RefreshToken) {
			rotatedAt := now.Add(time.Duration(rapid.Int64Range(0, int64(time.Second)).Draw(t, "rotate duration")))
			fresh := snapshot != nil && !snapshot.Rotated && now.Before(expiresAt)
			wantRotate := fresh && rotates && !revoked && i == current
			wantIssue := fresh && (!rotates || wantRotate && rotatedAt.Before(expiresAt))
			wantRevoke := snapshot != nil && (snapshot.Rotated || fresh && rotates && !revoked && i != current)
			effect, _, err := Refresh(snapshot, client, TokenRequest{}, []string{"read"}, reuseConfidential, now)
			if effect == RotateRefreshToken {
				before := load(i)
				if before != nil && !before.Rotated {
					stored[i].Rotated = true
					stored = append(stored, Successor(*before))
				}
				effect, err = Rotated(before, rotatedAt)
			}
			if (err == nil) != wantIssue || (effect == RevokeGrant) != wantRevoke {
				t.Fatalf("got effect %v and error %v refreshing with token %d of %d, want issue %v and Grant revocation %v", effect, err, i, len(stored), wantIssue, wantRevoke)
			}
			if effect == RevokeGrant {
				revoked = true
			}
			if wantRotate {
				current = len(stored) - 1
			}
			if wantIssue {
				issued[i]++
			}
		}
		t.Repeat(map[string]func(*rapid.T){
			"advance": func(t *rapid.T) {
				now = now.Add(time.Duration(rapid.Int64Range(0, int64(10*time.Minute)).Draw(t, "advance")))
			},
			"refresh": func(t *rapid.T) {
				i := rapid.IntRange(0, len(stored)-1).Draw(t, "token")
				refresh(t, i, load(i))
			},
			"refresh twice from one read": func(t *rapid.T) {
				i := rapid.IntRange(0, len(stored)-1).Draw(t, "token")
				snapshot := load(i)
				refresh(t, i, snapshot)
				refresh(t, i, snapshot)
			},
			"revoke": func(*rapid.T) {
				revoked = true
			},
			"": func(t *rapid.T) {
				for i, n := range issued {
					if rotates && n > 1 {
						t.Fatalf("issued tokens %d times for rotating refresh token %d", n, i)
					}
				}
				if !rotates && len(stored) > 1 {
					t.Fatalf("got %d refresh tokens, want the first one only without rotation", len(stored))
				}
			},
		})
	})
}

func TestRotatedRejectsRefreshTokenAtExpiry(t *testing.T) {
	expiresAt := time.Unix(1_000_000, 0)
	token := RefreshToken{ExpiresAt: expiresAt}
	if effect, err := Rotated(&token, expiresAt.Add(-time.Nanosecond)); err != nil || effect != NoEffect {
		t.Fatalf("got effect %v and error %v before expiry, want the token accepted", effect, err)
	}
	if effect, err := Rotated(&token, expiresAt); err == nil || effect != NoEffect {
		t.Fatalf("got effect %v and error %v at expiry, want the token rejected", effect, err)
	}
}

func TestIssueRefreshToken(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	code := Code{ClientID: "client", Scopes: []string{"read"}, RetainUntil: now.Add(time.Hour)}
	client := Client{ID: "client"}
	for lifetime, want := range map[time.Duration]time.Time{time.Minute: now.Add(time.Minute), 2 * time.Hour: code.RetainUntil} {
		got := IssueRefreshToken(client, code, now, lifetime)
		if got == nil || got.ClientID != "client" || !slices.Equal(got.Scopes, code.Scopes) || !got.ExpiresAt.Equal(want) || got.Rotated {
			t.Errorf("got %+v for lifetime %v, want it bound to the code and expiring at %v", got, lifetime, want)
		}
	}
	client.GrantTypes = []string{"authorization_code"}
	if got := IssueRefreshToken(client, code, now, time.Minute); got != nil {
		t.Errorf("got %+v for a Client that may not use refresh tokens, want none", got)
	}
}

func TestSuccessorKeepsScopesAndExpiry(t *testing.T) {
	token := RefreshToken{ClientID: "client", Scopes: []string{"read", "write"}, ExpiresAt: time.Unix(1_000_000, 0), Rotated: true}
	want := token
	want.Rotated = false
	if got := Successor(token); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestClientCredentials(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		client := Client{
			ID:            "client",
			Public:        rapid.Bool().Draw(t, "public"),
			AllowedScopes: rapid.SliceOfDistinct(rapid.SampledFrom([]string{"read", "write", "admin"}), rapid.ID).Draw(t, "allowed"),
			DefaultScopes: rapid.SliceOf(rapid.SampledFrom([]string{"read", "write", "admin"})).Draw(t, "defaults"),
		}
		requested := rapid.SampledFrom([]string{"", "read", "write read", "admin", "read admin"}).Draw(t, "scope")
		scopes, err := ClientCredentials(client, TokenRequest{Scope: requested}, supportedScopes)
		if client.Public {
			if err == nil || err.Code != "unauthorized_client" {
				t.Fatalf("got error %v for a public Client, want unauthorized_client", err)
			}
			return
		}
		if err != nil && err.Code != "invalid_scope" {
			t.Fatalf("got error %v, want invalid_scope or none", err)
		}
		if err == nil && len(scopes) == 0 {
			t.Fatal("got no scopes")
		}
		asked := client.DefaultScopes
		if requested != "" {
			asked = strings.Split(requested, " ")
		}
		for _, s := range scopes {
			if !slices.Contains(supportedScopes, s) || !slices.Contains(client.AllowedScopes, s) || !slices.Contains(asked, s) {
				t.Fatalf("got scopes %q for %q, allowed %q and defaults %q", scopes, requested, client.AllowedScopes, client.DefaultScopes)
			}
		}
	})
}

func TestClientCredentialsResolvesScopes(t *testing.T) {
	client := Client{ID: "client", AllowedScopes: []string{"read", "write"}, DefaultScopes: []string{"read"}}
	tests := map[string]struct {
		requested string
		want      []string
		code      string
	}{
		"default":     {"", []string{"read"}, ""},
		"requested":   {"write read", []string{"write", "read"}, ""},
		"not allowed": {"read admin", nil, "invalid_scope"},
		"unsupported": {"delete", nil, "invalid_scope"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			scopes, err := ClientCredentials(client, TokenRequest{Scope: tt.requested}, supportedScopes)
			if code := errorCode(err); code != tt.code || !slices.Equal(scopes, tt.want) {
				t.Fatalf("got scopes %q and error %q, want %q and %q", scopes, code, tt.want, tt.code)
			}
		})
	}
}
