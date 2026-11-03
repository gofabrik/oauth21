package oauth21_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/goleak"
	"pgregory.net/rapid"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/memstore"
	"github.com/gofabrik/oauth21/store"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// readScope is the scope the test Client is allowed and gets by default.
var readScope = []string{"read"}

const (
	issuer   = "https://as.example"
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func sum(v string) []byte {
	s := sha256.Sum256([]byte(v))
	return s[:]
}

func newServer(t testing.TB, m *memstore.Store, codes store.Codes, tokens store.Tokens) *oauth21.Server {
	t.Helper()
	if err := m.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}, AllowedScopes: readScope, DefaultScopes: readScope}); err != nil {
		t.Fatal(err)
	}
	srv, err := oauth21.New(oauth21.Config{
		Issuer:                issuer,
		LoginURL:              "/login",
		Clients:               m,
		AuthorizationRequests: m,
		Codes:                 codes,
		Tokens:                tokens,
		Scopes:                readScope,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

var authorizeQuery = url.Values{
	"response_type":         {"code"},
	"client_id":             {"client"},
	"state":                 {"xyz"},
	"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum(verifier))},
	"code_challenge_method": {"S256"},
}.Encode()

func tokenBody(code string) string {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"client"},
		"code_verifier": {verifier},
	}.Encode()
}

func do(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func tokenRequest(body string) *http.Request {
	return formRequest("/token", body)
}

// formRequest returns a POST of the form body to path over TLS.
func formRequest(path, body string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://as.example"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// accessToken returns the access token of a successful token response.
func accessToken(t testing.TB, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil || body.AccessToken == "" {
		t.Fatalf("got status %d and error %v, want an access token", w.Code, err)
	}
	return body.AccessToken
}

// requestID sends the authorization request query and returns the identifier of the pending Authorization Request.
func requestID(t rapid.TB, srv *oauth21.Server, query string) string {
	t.Helper()
	loc, err := url.Parse(do(srv.AuthorizationHandler(), httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://as.example/authorize?"+query, nil)).Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query().Get("request_id")
}

// issueCode runs an authorization request through Complete and returns the code.
func issueCode(t rapid.TB, srv *oauth21.Server) string {
	t.Helper()
	redirect, err := srv.Complete(context.Background(), requestID(t, srv, authorizeQuery), oauth21.Completion{Subject: "alice", Scopes: readScope})
	if err != nil {
		t.Fatal(err)
	}
	cb, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	return cb.Query().Get("code")
}

// tokenPair is the access token and the refresh token of a successful token response.
type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// tokens redeems a fresh code and returns the access token and the refresh token it issues.
func tokens(t rapid.TB, srv *oauth21.Server) tokenPair {
	t.Helper()
	var body tokenPair
	w := do(srv.TokenHandler(), tokenRequest(tokenBody(issueCode(t, srv))))
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil || body.RefreshToken == "" {
		t.Fatalf("got status %d and error %v, want a refresh token", w.Code, err)
	}
	return body
}

// refreshToken redeems a fresh code and returns the refresh token it issues.
func refreshToken(t rapid.TB, srv *oauth21.Server) string {
	t.Helper()
	return tokens(t, srv).RefreshToken
}

func TestCodeReplayRevokesGrant(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	code := issueCode(t, srv)

	token := accessToken(t, do(srv.TokenHandler(), tokenRequest(tokenBody(code))))
	if _, err := m.Token(t.Context(), sum(token)); err != nil {
		t.Fatal(err)
	}

	if w := do(srv.TokenHandler(), tokenRequest(tokenBody(code))); w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d for a replay, want 400", w.Code)
	}
	if _, err := m.Token(t.Context(), sum(token)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got error %v for the first access token, want it revoked", err)
	}
}

func TestCodeReplayRevokesTokenWithoutRefreshToken(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	if err := m.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}, AllowedScopes: readScope, DefaultScopes: readScope, GrantTypes: []string{"authorization_code"}}); err != nil {
		t.Fatal(err)
	}
	code := issueCode(t, srv)

	w := do(srv.TokenHandler(), tokenRequest(tokenBody(code)))
	var body tokenPair
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.AccessToken == "" || body.RefreshToken != "" {
		t.Fatalf("got status %d and body %s, want only an access token", w.Code, w.Body)
	}
	if w := do(srv.TokenHandler(), tokenRequest(tokenBody(code))); w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d for a replay, want 400", w.Code)
	}
	if _, err := m.Token(t.Context(), sum(body.AccessToken)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got error %v for the access token, want it revoked", err)
	}
}

func TestClientCredentialsCreatesGrantPerToken(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	hash, err := oauth21.PBKDF2{Iterations: 1}.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddClient(store.Client{ID: "service", Type: store.Confidential, AllowedScopes: readScope, DefaultScopes: readScope, SecretHash: hash, GrantTypes: []string{"client_credentials"}}); err != nil {
		t.Fatal(err)
	}
	body := "grant_type=client_credentials&client_id=service&client_secret=secret"
	var grants []store.Grant
	for range 2 {
		token, err := m.Token(t.Context(), sum(accessToken(t, do(srv.TokenHandler(), tokenRequest(body)))))
		if err != nil {
			t.Fatal(err)
		}
		grants = append(grants, token.Grant)
	}
	for _, g := range grants {
		if g.ID == "" || g.ClientID != "service" || g.Subject != "" || !slices.Equal(g.Scopes, readScope) {
			t.Fatalf("got Grant %+v, want one of the service Client with scope read and no Subject", g)
		}
	}
	if grants[0].ID == grants[1].ID {
		t.Fatalf("got Grant %q for both tokens, want one Grant per token", grants[0].ID)
	}
}

func TestConcurrentRedemptionLeavesNoToken(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	code := issueCode(t, srv)

	var wg sync.WaitGroup
	responses := make([]*httptest.ResponseRecorder, 8)
	for i := range responses {
		wg.Go(func() { responses[i] = do(srv.TokenHandler(), tokenRequest(tokenBody(code))) })
	}
	wg.Wait()
	replays := 0
	for _, w := range responses {
		switch w.Code {
		case http.StatusOK:
			if _, err := m.Token(t.Context(), sum(accessToken(t, w))); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("got error %v for an access token of a replayed code, want it revoked", err)
			}
		case http.StatusBadRequest:
			replays++
		default:
			t.Fatalf("got status %d", w.Code)
		}
	}
	if replays < len(responses)-1 {
		t.Fatalf("got %d failed redemptions, want at least %d", replays, len(responses)-1)
	}
}

// revokeFirst holds CreateToken until RevokeGrant has run, for at most a second.
type revokeFirst struct {
	*memstore.Store
	creating, revoked chan struct{}
	creatingOnce      sync.Once
	revokedOnce       sync.Once
}

func (r *revokeFirst) CreateToken(ctx context.Context, t store.Token) error {
	r.creatingOnce.Do(func() { close(r.creating) })
	select {
	case <-r.revoked:
	case <-time.After(time.Second):
		return errors.New("RevokeGrant was not called")
	}
	return r.Store.CreateToken(ctx, t)
}

func (r *revokeFirst) RevokeGrant(ctx context.Context, grantID string) error {
	defer r.revokedOnce.Do(func() { close(r.revoked) })
	return r.Store.RevokeGrant(ctx, grantID)
}

func TestTokenCreatedAfterRevocationIsRefused(t *testing.T) {
	m := memstore.New()
	tokens := &revokeFirst{Store: m, creating: make(chan struct{}), revoked: make(chan struct{})}
	srv := newServer(t, m, m, tokens)
	code := issueCode(t, srv)

	first := make(chan *httptest.ResponseRecorder)
	go func() { first <- do(srv.TokenHandler(), tokenRequest(tokenBody(code))) }()
	<-tokens.creating
	if w := do(srv.TokenHandler(), tokenRequest(tokenBody(code))); w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d for the replay, want 400", w.Code)
	}
	if w := <-first; w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d for the redemption that lost to a replay, want 400", w.Code)
	}
}

func TestCodeExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := memstore.New()
		srv := newServer(t, m, m, m)
		code := issueCode(t, srv)
		time.Sleep(time.Minute)
		if w := do(srv.TokenHandler(), tokenRequest(tokenBody(code))); w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d for an expired code, want 400", w.Code)
		}
	})
}

func TestReplayAfterCodeExpiryRevokesGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, tokens := memstore.New(), memstore.New()
		srv := newServer(t, m, m, tokens)
		code := issueCode(t, srv)
		token := accessToken(t, do(srv.TokenHandler(), tokenRequest(tokenBody(code))))
		time.Sleep(2 * time.Minute)
		issueCode(t, srv)
		if w := do(srv.TokenHandler(), tokenRequest(tokenBody(code))); w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d for a replay, want 400", w.Code)
		}
		if _, err := tokens.Token(t.Context(), sum(token)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("got error %v for the access token of a code replayed after expiry, want it revoked", err)
		}
	})
}

// slowConsume takes a minute to consume a code.
type slowConsume struct {
	*memstore.Store
}

func (s slowConsume) ConsumeCode(ctx context.Context, hash []byte) (store.Code, error) {
	time.Sleep(time.Minute)
	return s.Store.ConsumeCode(ctx, hash)
}

func TestCodeExpiringDuringConsumeIsRejected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := memstore.New()
		srv := newServer(t, m, slowConsume{m}, m)
		if w := do(srv.TokenHandler(), tokenRequest(tokenBody(issueCode(t, srv)))); w.Code != http.StatusBadRequest {
			t.Fatalf("got status %d for a code that expired while it was consumed, want 400", w.Code)
		}
	})
}

func TestTokenNeverOutlivesCodeRetention(t *testing.T) {
	for name, grantTypes := range map[string][]string{"with refresh token": nil, "without refresh token": {"authorization_code"}} {
		t.Run(name, func(t *testing.T) { testTokenNeverOutlivesCodeRetention(t, grantTypes) })
	}
}

func testTokenNeverOutlivesCodeRetention(t *testing.T, grantTypes []string) {
	synctest.Test(t, func(t *testing.T) {
		m := memstore.New()
		if err := m.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}, AllowedScopes: readScope, DefaultScopes: readScope, GrantTypes: grantTypes}); err != nil {
			t.Fatal(err)
		}
		withLifetime := func(lifetime time.Duration) *oauth21.Server {
			srv, err := oauth21.New(oauth21.Config{Issuer: issuer, Scopes: readScope, LoginURL: "/login", Clients: m, AuthorizationRequests: m, Codes: m, Tokens: m, AccessTokenLifetime: lifetime, RefreshTokenLifetime: lifetime})
			if err != nil {
				t.Fatal(err)
			}
			return srv
		}
		code := issueCode(t, withLifetime(time.Minute))
		w := do(withLifetime(time.Hour).TokenHandler(), tokenRequest(tokenBody(code)))
		var body struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int64  `json:"expires_in"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.ExpiresIn != 120 {
			t.Fatalf("got expires_in %d and error %v, want 120, the code lifetime plus the token lifetimes at issue", body.ExpiresIn, err)
		}
		if got, err := m.Token(t.Context(), sum(body.AccessToken)); err != nil || !got.ExpiresAt.Equal(time.Now().Add(2*time.Minute)) {
			t.Fatalf("got token %+v and error %v, want it to expire with the code's retention", got, err)
		}
	})
}

func TestNewCopiesScopes(t *testing.T) {
	m := memstore.New()
	if err := m.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}, AllowedScopes: readScope, DefaultScopes: readScope}); err != nil {
		t.Fatal(err)
	}
	scopes := []string{"read"}
	srv, err := oauth21.New(oauth21.Config{Issuer: issuer, Scopes: scopes, LoginURL: "/login", Clients: m, AuthorizationRequests: m, Codes: m, Tokens: m})
	if err != nil {
		t.Fatal(err)
	}
	scopes[0] = "admin"
	if requestID(t, srv, authorizeQuery) == "" {
		t.Fatal("got no Authorization Request after the configured scopes changed")
	}
}

func TestNewRequiresConfig(t *testing.T) {
	m := memstore.New()
	valid := oauth21.Config{
		Issuer:                issuer,
		LoginURL:              "/login",
		Clients:               m,
		AuthorizationRequests: m,
		Codes:                 m,
		Tokens:                m,
		Scopes:                readScope,
	}
	for name, change := range map[string]func(*oauth21.Config){
		"issuer":                         func(c *oauth21.Config) { c.Issuer = "" },
		"http issuer":                    func(c *oauth21.Config) { c.Issuer = "http://as.example" },
		"relative issuer":                func(c *oauth21.Config) { c.Issuer = "as.example" },
		"issuer with query":              func(c *oauth21.Config) { c.Issuer = "https://as.example?tenant=a" },
		"issuer with userinfo":           func(c *oauth21.Config) { c.Issuer = "https://user:pw@as.example" },
		"issuer without hostname":        func(c *oauth21.Config) { c.Issuer = "https://:443" },
		"issuer with non-ASCII host":     func(c *oauth21.Config) { c.Issuer = "https://bücher.example" },
		"issuer with empty port":         func(c *oauth21.Config) { c.Issuer = "https://as.example:" },
		"issuer with fragment":           func(c *oauth21.Config) { c.Issuer = "https://as.example#a" },
		"short request lifetime":         func(c *oauth21.Config) { c.AuthorizationRequestLifetime = time.Millisecond },
		"negative code lifetime":         func(c *oauth21.Config) { c.CodeLifetime = -time.Second },
		"long code lifetime":             func(c *oauth21.Config) { c.CodeLifetime = 11 * time.Minute },
		"negative token lifetime":        func(c *oauth21.Config) { c.AccessTokenLifetime = -time.Second },
		"short refresh lifetime":         func(c *oauth21.Config) { c.RefreshTokenLifetime = time.Millisecond },
		"short code lifetime":            func(c *oauth21.Config) { c.CodeLifetime = time.Millisecond },
		"short token lifetime":           func(c *oauth21.Config) { c.AccessTokenLifetime = 500 * time.Millisecond },
		"malformed login URL":            func(c *oauth21.Config) { c.LoginURL = "%zz" },
		"login URL":                      func(c *oauth21.Config) { c.LoginURL = "" },
		"client Store":                   func(c *oauth21.Config) { c.Clients = nil },
		"Authorization Request Store":    func(c *oauth21.Config) { c.AuthorizationRequests = nil },
		"code Store":                     func(c *oauth21.Config) { c.Codes = nil },
		"token Store":                    func(c *oauth21.Config) { c.Tokens = nil },
		"scopes":                         func(c *oauth21.Config) { c.Scopes = nil },
		"malformed scope":                func(c *oauth21.Config) { c.Scopes = []string{"read", "read write"} },
		"relative path":                  func(c *oauth21.Config) { c.Paths.Token = "token" },
		"revocation path with query":     func(c *oauth21.Config) { c.Paths.Revocation = "/revoke?a=b" },
		"introspection path with query":  func(c *oauth21.Config) { c.Paths.Introspection = "/introspect?a=b" },
		"empty query":                    func(c *oauth21.Config) { c.Paths.Authorization = "/authorize?" },
		"query with fragment":            func(c *oauth21.Config) { c.Paths.Authorization = "/authorize?a=b#c" },
		"query with space":               func(c *oauth21.Config) { c.Paths.Token = "/token?a=b c" },
		"malformed query":                func(c *oauth21.Config) { c.Paths.Token = "/token?a=%zz" },
		"query with non-ASCII":           func(c *oauth21.Config) { c.Paths.Token = "/token?a=é" },
		"query naming a request param":   func(c *oauth21.Config) { c.Paths.Authorization = "/authorize?scope=admin" },
		"query with angle brackets":      func(c *oauth21.Config) { c.Paths.Authorization = "/authorize?a=<b>" },
		"query with backslash":           func(c *oauth21.Config) { c.Paths.Token = `/token?a=b\c` },
		"unclean path with query":        func(c *oauth21.Config) { c.Paths.Token = "/oauth/../token?a=b" },
		"duplicate path with query":      func(c *oauth21.Config) { c.Paths.Token = "/authorize?a=b" },
		"path with fragment":             func(c *oauth21.Config) { c.Paths.Revocation = "/revoke#a" },
		"malformed path":                 func(c *oauth21.Config) { c.Paths.Introspection = "/%zz" },
		"path with space":                func(c *oauth21.Config) { c.Paths.Token = "/oauth token" },
		"path with empty segment":        func(c *oauth21.Config) { c.Paths.Token = "//oauth/token" },
		"path with dot segment":          func(c *oauth21.Config) { c.Paths.Token = "/oauth/../token" },
		"path with trailing slash":       func(c *oauth21.Config) { c.Paths.Token = "/oauth/" },
		"escaped path":                   func(c *oauth21.Config) { c.Paths.Token = "/oauth%20token" },
		"path with wildcard":             func(c *oauth21.Config) { c.Paths.Token = "/{token}" },
		"duplicate path":                 func(c *oauth21.Config) { c.Paths.Token, c.Paths.Revocation = "/oauth", "/oauth" },
		"path of another default":        func(c *oauth21.Config) { c.Paths.Token = "/authorize" },
		"root path":                      func(c *oauth21.Config) { c.Paths.Token = "/" },
		"metadata path":                  func(c *oauth21.Config) { c.Paths.Token = "/.well-known/oauth-authorization-server" },
		"issuer path with space":         func(c *oauth21.Config) { c.Issuer = "https://as.example/a b" },
		"issuer path with wildcard":      func(c *oauth21.Config) { c.Issuer = "https://as.example/{t}" },
		"issuer path with empty segment": func(c *oauth21.Config) { c.Issuer = "https://as.example//x" },
		"issuer path with dot segment":   func(c *oauth21.Config) { c.Issuer = "https://as.example/a/../b" },
		"escaped issuer path":            func(c *oauth21.Config) { c.Issuer = "https://as.example/a%2Fb" },
		"issuer with empty path":         func(c *oauth21.Config) { c.Issuer = "https://as.example//" },
		"negative lockout failures":      func(c *oauth21.Config) { c.Lockout.Failures = -1 },
		"short lockout duration":         func(c *oauth21.Config) { c.Lockout.Duration = time.Millisecond },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			change(&c)
			if _, err := oauth21.New(c); err == nil {
				t.Fatal("got no error, want the Config to be rejected")
			}
		})
	}
	if _, err := oauth21.New(valid); err != nil {
		t.Fatal(err)
	}
}

func TestNewAcceptsTokenQueryNamingAuthorizationParam(t *testing.T) {
	m := memstore.New()
	if _, err := oauth21.New(oauth21.Config{Issuer: issuer, Paths: oauth21.Paths{Token: "/token?client_id=c"}, LoginURL: "/login", Clients: m, AuthorizationRequests: m, Codes: m, Tokens: m, Scopes: readScope}); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataNamesEndpointQueries(t *testing.T) {
	m := memstore.New()
	srv, err := oauth21.New(oauth21.Config{Issuer: issuer + "/tenant/", Paths: oauth21.Paths{Authorization: "/authorize?realm=a", Token: "/oauth/token?realm=a&v=1"}, LoginURL: "/login", Clients: m, AuthorizationRequests: m, Codes: m, Tokens: m, Scopes: readScope}) // #nosec G101 -- endpoint paths, not credentials
	if err != nil {
		t.Fatal(err)
	}
	w := do(srv.MetadataHandler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, issuer+srv.MetadataPath(), nil))
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"authorization_endpoint": issuer + "/tenant/authorize?realm=a",
		"token_endpoint":         issuer + "/tenant/oauth/token?realm=a&v=1",
		"revocation_endpoint":    issuer + "/tenant/revoke",
		"introspection_endpoint": issuer + "/tenant/introspect",
	} {
		if got[name] != want {
			t.Errorf("got %s %v, want %s", name, got[name], want)
		}
	}
}

func TestPaths(t *testing.T) {
	m := memstore.New()
	for _, tt := range []struct {
		issuer       string
		paths        oauth21.Paths
		want         oauth21.Paths
		wantMetadata string
	}{
		{issuer, oauth21.Paths{}, oauth21.Paths{Authorization: "/authorize", Token: "/token", Revocation: "/revoke", Introspection: "/introspect"}, "/.well-known/oauth-authorization-server"},
		{issuer + "/", oauth21.Paths{Token: "/oauth/token"}, oauth21.Paths{Authorization: "/authorize", Token: "/oauth/token", Revocation: "/revoke", Introspection: "/introspect"}, "/.well-known/oauth-authorization-server"},                                                                               // #nosec G101 -- endpoint paths, not credentials
		{issuer + "/tenant/", oauth21.Paths{Token: "/oauth/token"}, oauth21.Paths{Authorization: "/tenant/authorize", Token: "/tenant/oauth/token", Revocation: "/tenant/revoke", Introspection: "/tenant/introspect"}, "/.well-known/oauth-authorization-server/tenant"},                                     // #nosec G101 -- endpoint paths, not credentials
		{issuer + "/tenant", oauth21.Paths{Authorization: "/authorize?realm=a", Token: "/token?realm=a&v=1"}, oauth21.Paths{Authorization: "/tenant/authorize", Token: "/tenant/token", Revocation: "/tenant/revoke", Introspection: "/tenant/introspect"}, "/.well-known/oauth-authorization-server/tenant"}, // #nosec G101 -- endpoint paths, not credentials
	} {
		srv, err := oauth21.New(oauth21.Config{Issuer: tt.issuer, Paths: tt.paths, LoginURL: "/login", Clients: m, AuthorizationRequests: m, Codes: m, Tokens: m, Scopes: readScope})
		if err != nil {
			t.Fatal(err)
		}
		if got := srv.Paths(); got != tt.want {
			t.Errorf("%s: got paths %+v, want %+v", tt.issuer, got, tt.want)
		}
		if got := srv.MetadataPath(); got != tt.wantMetadata {
			t.Errorf("%s: got metadata path %q, want %q", tt.issuer, got, tt.wantMetadata)
		}
	}
}

// authorizationErrors are the error codes the authorization endpoint may redirect with.
var authorizationErrors = map[string]bool{
	"invalid_request":           true,
	"unauthorized_client":       true,
	"access_denied":             true,
	"unsupported_response_type": true,
	"invalid_scope":             true,
	"server_error":              true,
	"temporarily_unavailable":   true,
}

// tokenErrors are the error codes the token endpoint may return.
var tokenErrors = map[string]bool{
	"invalid_request":        true,
	"invalid_client":         true,
	"invalid_grant":          true,
	"unauthorized_client":    true,
	"unsupported_grant_type": true,
	"invalid_scope":          true,
}

// revocationErrors are the error codes the revocation endpoint may return.
var revocationErrors = map[string]bool{
	"invalid_request": true,
	"invalid_client":  true,
	"invalid_grant":   true,
}

// introspectionErrors are the error codes the introspection endpoint may return.
var introspectionErrors = map[string]bool{
	"invalid_request":     true,
	"invalid_client":      true,
	"unauthorized_client": true,
}

func FuzzAuthorizationHandler(f *testing.F) {
	f.Add(false, authorizeQuery)
	f.Add(true, authorizeQuery)
	f.Add(false, authorizeQuery+"&client_id=client")
	f.Add(false, authorizeQuery+"&scope=read+read")
	f.Add(false, authorizeQuery+"&scope=read+write")
	f.Add(false, strings.Replace(authorizeQuery, "S256", "plain", 1))
	f.Add(false, "client_id=%zz&redirect_uri=http://127.0.0.1:1/cb")
	m := memstore.New()
	h := newServer(f, m, m, m).AuthorizationHandler()
	f.Fuzz(func(t *testing.T, post bool, params string) {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://as.example/authorize", nil)
		r.URL.RawQuery = params
		if post {
			r = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://as.example/authorize", strings.NewReader(params))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		w := do(h, r)
		redirect := http.StatusFound
		if post {
			redirect = http.StatusSeeOther
		}
		if w.Code >= 500 || w.Code != redirect && w.Header().Get("Location") != "" {
			t.Fatalf("got status %d and Location %q", w.Code, w.Header().Get("Location"))
		}
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if code := loc.Query().Get("error"); loc.Query().Has("error") && !authorizationErrors[code] {
			t.Fatalf("got error %q", code)
		}
	})
}

// FuzzTokenHandler fuzzes token requests in which CODE stands for a freshly issued code and REFRESH for a fresh refresh token.
func FuzzTokenHandler(f *testing.F) {
	f.Add(tokenBody("CODE"), "")
	f.Add(tokenBody("CODE")+"&code=other", "")
	f.Add(strings.Replace(tokenBody("CODE"), "dBjf", "xBjf", 1), "")
	f.Add(tokenBody("CODE")+"&client_secret=s", "")
	f.Add(strings.Replace(tokenBody("CODE"), "client_id=client", "client_id=confidential&client_secret=secret", 1), "")
	f.Add(tokenBody("CODE"), "Basic Y29uZmlkZW50aWFsOnNlY3JldA==")
	f.Add(tokenBody("CODE"), "Basic !")
	f.Add(tokenBody("CODE"), "Bearer x")
	f.Add("grant_type=refresh_token&refresh_token=REFRESH&client_id=client", "")
	f.Add("grant_type=refresh_token&refresh_token=REFRESH&client_id=client&scope=read", "")
	f.Add("grant_type=refresh_token&refresh_token=REFRESH&client_id=client&scope=admin", "")
	f.Add("grant_type=refresh_token&refresh_token=REFRESH", "Basic Y29uZmlkZW50aWFsOnNlY3JldA==")
	f.Add("grant_type=client_credentials", "")
	f.Add("grant_type=client_credentials", "Basic Y29uZmlkZW50aWFsOnNlY3JldA==")
	f.Add("grant_type=client_credentials&scope=read", "Basic Y29uZmlkZW50aWFsOnNlY3JldA==")
	f.Add("grant_type=client_credentials&scope=admin&client_id=confidential&client_secret=secret", "")
	f.Add("grant_type=client_credentials&client_id=client", "")
	f.Add("%zz", "")
	hash, err := oauth21.PBKDF2{Iterations: 1}.Hash("secret")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, body, authorization string) {
		m := memstore.New()
		if err := m.AddClient(store.Client{ID: "confidential", Type: store.Confidential, RedirectURIs: []string{"https://client.example/cb"}, AllowedScopes: readScope, DefaultScopes: readScope, SecretHash: hash, GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"}}); err != nil {
			t.Fatal(err)
		}
		srv := newServer(t, m, m, m)
		body = strings.ReplaceAll(body, "CODE", issueCode(t, srv))
		if strings.Contains(body, "REFRESH") {
			body = strings.ReplaceAll(body, "REFRESH", refreshToken(t, srv))
		}
		r := tokenRequest(body)
		r.Header["Authorization"] = []string{authorization}
		w := do(srv.TokenHandler(), r)
		var resp struct {
			Error       string
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if w.Code == http.StatusOK && resp.AccessToken == "" || w.Code != http.StatusOK && !tokenErrors[resp.Error] {
			t.Fatalf("got status %d and body %+v", w.Code, resp)
		}
		if resp.Error == "invalid_client" && authorization != "" && (w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "") {
			t.Fatalf("got status %d and WWW-Authenticate %q for a failed Authorization header, want 401 with a challenge", w.Code, w.Header().Get("WWW-Authenticate"))
		}
	})
}

// acceptSecret is a SecretHasher that accepts the secret "secret" for the hash "hash".
type acceptSecret struct{}

func (acceptSecret) Hash(string) (string, error) { return "hash", nil }

func (acceptSecret) Verify(hash, secret string) bool { return hash == "hash" && secret == "secret" }

func TestSecretHasherVerifiesSecrets(t *testing.T) {
	m := memstore.New()
	if err := m.AddClient(store.Client{ID: "client", Type: store.Confidential, RedirectURIs: []string{"https://client.example/cb"}, AllowedScopes: readScope, DefaultScopes: readScope, SecretHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	srv, err := oauth21.New(oauth21.Config{
		Issuer:                issuer,
		LoginURL:              "/login",
		Clients:               m,
		AuthorizationRequests: m,
		Codes:                 m,
		Tokens:                m,
		Scopes:                readScope,
		SecretHasher:          acceptSecret{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for secret, want := range map[string]int{"wrong": http.StatusBadRequest, "secret": http.StatusOK} {
		w := do(srv.TokenHandler(), tokenRequest(tokenBody(issueCode(t, srv))+"&client_secret="+secret))
		if w.Code != want {
			t.Fatalf("got status %d with secret %q, want %d", w.Code, secret, want)
		}
	}
}

// failingStores fails the Client lookups, the Resource Server lookups and the Authorization Request Store when set.
type failingStores struct {
	*memstore.Store
	clients, resourceServers, requests bool
}

func (f *failingStores) ResourceServer(ctx context.Context, resource string) (store.Client, error) {
	if f.resourceServers {
		return store.Client{}, errors.New("resource server lookup down")
	}
	return f.Store.ResourceServer(ctx, resource)
}

func (f *failingStores) Client(ctx context.Context, id string) (store.Client, error) {
	if f.clients {
		return store.Client{}, errors.New("client Store down")
	}
	return f.Store.Client(ctx, id)
}

func (f *failingStores) CreateAuthorizationRequest(ctx context.Context, r store.AuthorizationRequest) error {
	if f.requests {
		return errors.New("Authorization Request Store down")
	}
	return f.Store.CreateAuthorizationRequest(ctx, r)
}

func TestErrorsBeforeHandOffAreRendered(t *testing.T) {
	tests := map[string]struct {
		query  string
		stores failingStores
		status int
		code   string
	}{
		"unknown client":                {strings.Replace(authorizeQuery, "client_id=client", "client_id=other", 1), failingStores{}, http.StatusBadRequest, "invalid_request"},
		"repeated parameter":            {authorizeQuery + "&client_id=client", failingStores{}, http.StatusBadRequest, "invalid_request"},
		"client Store failure":          {authorizeQuery, failingStores{clients: true}, http.StatusInternalServerError, "server_error"},
		"unknown client with resource":  {strings.Replace(authorizeQuery, "client_id=client", "client_id=other", 1) + "&resource=https%3A%2F%2Frs.example%2Fapi", failingStores{resourceServers: true}, http.StatusBadRequest, "invalid_request"},
		"Resource Server Store failure": {authorizeQuery + "&resource=https%3A%2F%2Frs.example%2Fapi", failingStores{resourceServers: true}, http.StatusInternalServerError, "server_error"},
		"request Store failure":         {authorizeQuery, failingStores{requests: true}, http.StatusInternalServerError, "server_error"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := tt.stores
			f.Store = memstore.New()
			if err := f.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}, AllowedScopes: readScope, DefaultScopes: readScope}); err != nil {
				t.Fatal(err)
			}
			var got oauth21.AuthorizationError
			srv, err := oauth21.New(oauth21.Config{
				Issuer:                issuer,
				LoginURL:              "/login",
				Clients:               &f,
				AuthorizationRequests: &f,
				Codes:                 f.Store,
				Tokens:                f.Store,
				Scopes:                readScope,
				RenderError: func(w http.ResponseWriter, _ *http.Request, e oauth21.AuthorizationError) {
					got = e
					w.WriteHeader(http.StatusTeapot)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			w := do(srv.AuthorizationHandler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://as.example/authorize?"+tt.query, nil))
			if w.Code != http.StatusTeapot || got.Status != tt.status || got.Code != tt.code {
				t.Fatalf("got status %d and rendered error %+v, want the renderer called with %d and %q", w.Code, got, tt.status, tt.code)
			}
		})
	}
}

func TestConcurrentCompletionAndDenialSucceedOnce(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	id := requestID(t, srv, authorizeQuery)

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			if i%2 == 0 {
				_, errs[i] = srv.Complete(t.Context(), id, oauth21.Completion{Subject: "alice", Scopes: readScope})
			} else {
				_, errs[i] = srv.Deny(t.Context(), id)
			}
		})
	}
	wg.Wait()
	succeeded := 0
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case !errors.Is(err, oauth21.ErrRequestNotPending):
			t.Fatalf("got error %v, want ErrRequestNotPending", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("got %d successful completions and denials, want 1", succeeded)
	}
}

func TestAuthorizationRequestExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := memstore.New()
		srv := newServer(t, m, m, m)
		expired := requestID(t, srv, authorizeQuery)
		time.Sleep(10*time.Minute - time.Second)
		live := requestID(t, srv, authorizeQuery)
		time.Sleep(time.Second)
		if _, err := srv.Complete(t.Context(), expired, oauth21.Completion{Subject: "alice", Scopes: readScope}); !errors.Is(err, oauth21.ErrRequestNotPending) {
			t.Fatalf("got error %v completing an expired request, want ErrRequestNotPending", err)
		}
		if _, err := srv.Deny(t.Context(), expired); !errors.Is(err, oauth21.ErrRequestNotPending) {
			t.Fatalf("got error %v denying an expired request, want ErrRequestNotPending", err)
		}
		if _, err := srv.Deny(t.Context(), live); err != nil {
			t.Fatalf("got error %v denying a pending request", err)
		}
	})
}

// TestAuthorizationRequestLifecycle checks Authorization Requests, valid or failed, against a model of pending requests and their expiry.
func TestAuthorizationRequestLifecycle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		now := time.Unix(1_000_000, 0)
		m := memstore.NewWithClock(func() time.Time { return now })
		if err := m.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}, AllowedScopes: readScope, DefaultScopes: readScope}); err != nil {
			t.Fatal(err)
		}
		srv, err := oauth21.New(oauth21.Config{
			Issuer:                       issuer,
			LoginURL:                     "/login",
			Clients:                      m,
			AuthorizationRequests:        m,
			Codes:                        m,
			Tokens:                       m,
			Scopes:                       readScope,
			AuthorizationRequestLifetime: time.Minute,
			Clock:                        func() time.Time { return now },
		})
		if err != nil {
			t.Fatal(err)
		}
		pending := map[string]time.Time{}
		failed := map[string]bool{}
		ids := []string{"unknown"}
		draw := func(t *rapid.T) (string, bool) {
			id := rapid.SampledFrom(ids).Draw(t, "id")
			expiresAt, ok := pending[id]
			return id, ok && now.Before(expiresAt)
		}
		wantPending := func(t *rapid.T, err error, want bool) {
			if want && err != nil || !want && !errors.Is(err, oauth21.ErrRequestNotPending) {
				t.Fatalf("got error %v, want pending %v", err, want)
			}
		}
		t.Repeat(map[string]func(*rapid.T){
			"authorize": func(t *rapid.T) {
				id := requestID(t, srv, authorizeQuery)
				pending[id] = now.Add(time.Minute)
				ids = append(ids, id)
			},
			"authorize failing": func(t *rapid.T) {
				id := requestID(t, srv, authorizeQuery+"&scope=unknown")
				pending[id] = now.Add(time.Minute)
				failed[id] = true
				ids = append(ids, id)
			},
			"advance": func(t *rapid.T) {
				now = now.Add(time.Duration(rapid.Int64Range(0, int64(time.Minute)).Draw(t, "advance")))
			},
			"read": func(t *rapid.T) {
				id, want := draw(t)
				req, err := srv.AuthorizationRequest(context.Background(), id)
				wantPending(t, err, want)
				if want && (req.Error != nil && req.Error.Code == "invalid_scope") != failed[id] {
					t.Fatalf("got error %+v, want failed %v", req.Error, failed[id])
				}
			},
			"complete without subject": func(t *rapid.T) {
				id, want := draw(t)
				_, err := srv.Complete(context.Background(), id, oauth21.Completion{})
				if want && !errors.Is(err, oauth21.ErrInvalidCompletion) || !want && !errors.Is(err, oauth21.ErrRequestNotPending) {
					t.Fatalf("got error %v for a Completion without subject, want pending %v", err, want)
				}
			},
			"complete": func(t *rapid.T) {
				id, want := draw(t)
				redirect, err := srv.Complete(context.Background(), id, oauth21.Completion{Subject: "alice", Scopes: readScope})
				if want && failed[id] {
					if !errors.Is(err, oauth21.ErrInvalidCompletion) {
						t.Fatalf("got error %v completing a failed request, want ErrInvalidCompletion", err)
					}
					return
				}
				wantPending(t, err, want)
				if want && !strings.Contains(redirect, "code=") {
					t.Fatalf("got redirect %q, want a code", redirect)
				}
				delete(pending, id)
			},
			"deny": func(t *rapid.T) {
				id, want := draw(t)
				redirect, err := srv.Deny(context.Background(), id)
				wantPending(t, err, want)
				wantError := "error=access_denied"
				if failed[id] {
					wantError = "error=invalid_scope"
				}
				if want && !strings.Contains(redirect, wantError) {
					t.Fatalf("got redirect %q, want %s", redirect, wantError)
				}
				delete(pending, id)
			},
		})
	})
}

func TestFailedAuthorizationRequestDescribesItsError(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	req, err := srv.AuthorizationRequest(t.Context(), requestID(t, srv, authorizeQuery+"&scope=unknown"))
	if err != nil || req.Error == nil || *req.Error != (oauth21.AuthorizationError{Status: http.StatusBadRequest, Code: "invalid_scope", Description: "scope not available to the client"}) {
		t.Fatalf("got request %+v and error %v, want invalid_scope with its description", req, err)
	}
	if req, err := srv.AuthorizationRequest(t.Context(), requestID(t, srv, authorizeQuery)); err != nil || req.Error != nil {
		t.Fatalf("got request %+v and error %v, want a valid request", req, err)
	}
}

// TestRequestedResourcesBoundAudience checks that the Host Application sees the requested Resource URIs and can complete only with an audience among them.
func TestRequestedResourcesBoundAudience(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	for _, uri := range []string{"https://a.example/api", "https://b.example/api"} {
		if err := m.AddClient(store.Client{ID: uri, Type: store.Confidential, Resource: uri}); err != nil {
			t.Fatal(err)
		}
	}
	id := requestID(t, srv, authorizeQuery+"&resource=https%3A%2F%2FA.example%2Fapi")
	if req, err := srv.AuthorizationRequest(t.Context(), id); err != nil || !slices.Equal(req.Resources, []string{"https://a.example/api"}) {
		t.Fatalf("got request %+v and error %v, want the requested Resource URI", req, err)
	}
	for _, audience := range [][]string{nil, {"https://b.example/api"}, {"https://a.example/api", "https://b.example/api"}} {
		if _, err := srv.Complete(t.Context(), id, oauth21.Completion{Subject: "alice", Scopes: readScope, Audience: audience}); !errors.Is(err, oauth21.ErrInvalidCompletion) {
			t.Fatalf("got error %v completing with audience %q, want ErrInvalidCompletion", err, audience)
		}
	}
	if _, err := srv.Complete(t.Context(), id, oauth21.Completion{Subject: "alice", Scopes: readScope, Audience: []string{"https://a.example/api"}}); err != nil {
		t.Fatalf("got error %v completing with the requested audience", err)
	}
}

// countingStore counts the lookups of Resource Servers.
type countingStore struct {
	*memstore.Store
	lookups int
}

func (c *countingStore) ResourceServer(ctx context.Context, resource string) (store.Client, error) {
	c.lookups++
	return c.Store.ResourceServer(ctx, resource)
}

// TestRepeatedResourceIsLookedUpOnce checks that a Resource URI repeated in resource, also with another case of the scheme and host, is looked up once.
func TestRepeatedResourceIsLookedUpOnce(t *testing.T) {
	c := &countingStore{Store: memstore.New()}
	if err := c.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}, AllowedScopes: readScope, DefaultScopes: readScope}); err != nil {
		t.Fatal(err)
	}
	srv, err := oauth21.New(oauth21.Config{Issuer: issuer, LoginURL: "/login", Clients: c, AuthorizationRequests: c.Store, Codes: c.Store, Tokens: c.Store, Scopes: readScope})
	if err != nil {
		t.Fatal(err)
	}
	requestID(t, srv, authorizeQuery+strings.Repeat("&resource=https%3A%2F%2Frs.example%2Fapi&resource=HTTPS%3A%2F%2FRS.example%2Fapi", 50))
	if c.lookups != 1 {
		t.Fatalf("got %d lookups of a repeated Resource URI, want 1", c.lookups)
	}
}

func TestAuthorizationRequestOfUntypedClientFails(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	id := requestID(t, srv, authorizeQuery)
	untyped, err := m.Client(t.Context(), "client")
	if err != nil {
		t.Fatal(err)
	}
	untyped.Type = 0
	if err := m.AddClient(untyped); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.AuthorizationRequest(t.Context(), id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got error %v for an Authorization Request of a Client without a type, want store.ErrNotFound", err)
	}
}

func TestEmptyRegisteredRedirectURIIsRendered(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	if err := m.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{""}, AllowedScopes: readScope, DefaultScopes: readScope}); err != nil {
		t.Fatal(err)
	}
	w := do(srv.AuthorizationHandler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://as.example/authorize?"+authorizeQuery, nil))
	if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Fatalf("got status %d and Location %q, want 400 without redirect", w.Code, w.Header().Get("Location"))
	}
}

// TestRefreshTokenFamily checks the refresh tokens of a Grant, and the introspection of its access tokens, over HTTP against a model of rotation, reuse, revocation, token revocation and expiry.
func TestRefreshTokenFamily(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		now := time.Unix(1_000_000, 0)
		clock := func() time.Time { return now }
		m := memstore.NewWithClock(clock)
		public := rapid.Bool().Draw(t, "public")
		reuse := rapid.Bool().Draw(t, "reuse confidential")
		srv, err := oauth21.New(oauth21.Config{
			Issuer:                         issuer,
			LoginURL:                       "/login",
			Clients:                        m,
			AuthorizationRequests:          m,
			Codes:                          m,
			Tokens:                         m,
			Scopes:                         readScope,
			SecretHasher:                   acceptSecret{},
			AccessTokenLifetime:            2 * time.Hour,
			RefreshTokenLifetime:           time.Hour,
			ReuseConfidentialRefreshTokens: reuse,
			Clock:                          clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		client := store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}, AllowedScopes: readScope, DefaultScopes: readScope}
		credentials := ""
		if !public {
			client.Type, client.SecretHash, credentials = store.Confidential, "hash", "&client_secret=secret"
		}
		if err := m.AddClient(client); err != nil {
			t.Fatal(err)
		}
		if err := m.AddClient(store.Client{ID: "rs", Type: store.Confidential, SecretHash: "hash", Introspect: true}); err != nil {
			t.Fatal(err)
		}
		w := do(srv.TokenHandler(), tokenRequest(tokenBody(issueCode(t, srv))+credentials))
		var body tokenPair
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil || body.RefreshToken == "" {
			t.Fatalf("got status %d and error %v, want a refresh token", w.Code, err)
		}
		expiresAt := now.Add(time.Hour)
		rotates := public || !reuse
		refreshTokens, accessTokens := []string{body.RefreshToken, "unknown"}, []string{body.AccessToken}
		current, revoked, revokedTokens := 0, false, map[string]bool{}
		t.Repeat(map[string]func(*rapid.T){
			"advance": func(t *rapid.T) {
				now = now.Add(time.Duration(rapid.Int64Range(0, int64(20*time.Minute)).Draw(t, "advance")))
			},
			"refresh": func(t *rapid.T) {
				i := rapid.IntRange(0, len(refreshTokens)-1).Draw(t, "refresh token")
				live := !revoked && now.Before(expiresAt)
				wantOK := live && i == current
				w := do(srv.TokenHandler(), tokenRequest("grant_type=refresh_token&client_id=client&refresh_token="+refreshTokens[i]+credentials))
				if (w.Code == http.StatusOK) != wantOK {
					t.Fatalf("got status %d refreshing with token %d of %d, want success %v", w.Code, i, len(refreshTokens), wantOK)
				}
				if live && rotates && i != current && refreshTokens[i] != "unknown" {
					revoked = true
				}
				if !wantOK {
					return
				}
				var body tokenPair
				if err := json.NewDecoder(w.Body).Decode(&body); err != nil || (body.RefreshToken != "") != rotates {
					t.Fatalf("got refresh token %q and error %v, want a new one %v", body.RefreshToken, err, rotates)
				}
				accessTokens = append(accessTokens, body.AccessToken)
				if rotates {
					refreshTokens = append(refreshTokens, body.RefreshToken)
					current = len(refreshTokens) - 1
				}
			},
			"revoke": func(t *rapid.T) {
				live := !revoked && now.Before(expiresAt)
				token := rapid.SampledFrom(append(slices.Clone(refreshTokens), accessTokens...)).Draw(t, "token")
				if w := do(srv.RevocationHandler(), formRequest("/revoke", "client_id=client&token="+token+credentials)); w.Code != http.StatusOK {
					t.Fatalf("got status %d revoking a token of the Client, want 200", w.Code)
				}
				switch {
				case !live:
				case slices.Contains(accessTokens, token):
					revokedTokens[token] = true
				case token != "unknown":
					revoked = true
				}
			},
			"": func(t *rapid.T) {
				for _, a := range accessTokens {
					got, err := m.Token(context.Background(), sum(a))
					switch {
					case (revoked || revokedTokens[a]) && !errors.Is(err, store.ErrNotFound):
						t.Fatalf("got token %+v and error %v after it or its Grant was revoked, want ErrNotFound", got, err)
					case err == nil && got.ExpiresAt.After(expiresAt):
						t.Fatalf("got an access token expiring at %v, after its Refresh Token Family at %v", got.ExpiresAt, expiresAt)
					}
					var resp struct{ Active bool }
					w := do(srv.IntrospectionHandler(), formRequest("/introspect", "client_id=rs&client_secret=secret&token="+a))
					if err := json.NewDecoder(w.Body).Decode(&resp); err != nil || w.Code != http.StatusOK {
						t.Fatalf("got status %d and error %v introspecting an access token, want 200", w.Code, err)
					}
					if want := !revoked && !revokedTokens[a] && now.Before(expiresAt); resp.Active != want {
						t.Fatalf("got active %v introspecting an access token, want %v", resp.Active, want)
					}
				}
			},
		})
	})
}

// TestIntrospectionChecksAudience checks that an access token with an audience introspects as active only for a Client whose Resource URI is in it.
func TestIntrospectionChecksAudience(t *testing.T) {
	hash, err := oauth21.PBKDF2{Iterations: 1}.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	m := memstore.New()
	srv := newServer(t, m, m, m)
	if err := m.AddClient(store.Client{ID: "rs-a", Type: store.Confidential, SecretHash: hash, Introspect: true, Resource: "https://a.example/api"}); err != nil {
		t.Fatal(err)
	}
	if err := m.AddClient(store.Client{ID: "rs-b", Type: store.Confidential, SecretHash: hash, Introspect: true, Resource: "https://b.example/api"}); err != nil {
		t.Fatal(err)
	}
	grant := store.Grant{ID: "grant", ClientID: "client", Subject: "alice", Scopes: readScope, Audience: []string{"https://a.example/api"}}
	if err := m.CreateToken(t.Context(), store.Token{Hash: sum("token"), Grant: grant, Scopes: readScope, Audience: grant.Audience, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for caller, want := range map[string]bool{"rs-a": true, "rs-b": false} {
		w := do(srv.IntrospectionHandler(), formRequest("/introspect", "token=token&client_secret=secret&client_id="+caller))
		var resp struct {
			Active   bool
			Audience []string `json:"aud"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil || w.Code != http.StatusOK || resp.Active != want || want && !slices.Equal(resp.Audience, grant.Audience) {
			t.Errorf("%s: got status %d, %+v and error %v, want active %v with the token's audience", caller, w.Code, resp, err, want)
		}
	}
}

func TestRevocationOfAnotherClientsTokenIsRefused(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	if err := m.AddClient(store.Client{ID: "other", Type: store.Public}); err != nil {
		t.Fatal(err)
	}
	body := tokens(t, srv)
	for _, token := range []string{body.AccessToken, body.RefreshToken} {
		w := do(srv.RevocationHandler(), formRequest("/revoke", "client_id=other&token="+token))
		var resp struct{ Error string }
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil || w.Code != http.StatusBadRequest || resp.Error != "invalid_grant" {
			t.Fatalf("got status %d, error %q and %v revoking another Client's token, want 400 and invalid_grant", w.Code, resp.Error, err)
		}
	}
	if _, err := m.Token(t.Context(), sum(body.AccessToken)); err != nil {
		t.Fatalf("got error %v for an access token another Client tried to revoke, want it kept", err)
	}
	if _, err := m.RefreshToken(t.Context(), sum(body.RefreshToken)); err != nil {
		t.Fatalf("got error %v for a refresh token another Client tried to revoke, want it kept", err)
	}
}

// FuzzRevocationHandler fuzzes revocation requests in which ACCESS and REFRESH stand for a fresh access token and refresh token of the public Client.
func FuzzRevocationHandler(f *testing.F) {
	f.Add("token=REFRESH&client_id=client", "")
	f.Add("token=ACCESS&client_id=client&token_type_hint=refresh_token", "")
	f.Add("token=unknown&client_id=client", "")
	f.Add("token=REFRESH&client_id=confidential&client_secret=secret", "")
	f.Add("token=ACCESS", "Basic Y29uZmlkZW50aWFsOnNlY3JldA==")
	f.Add("token=ACCESS&client_id=client", "Bearer x")
	f.Add("token=a&token=b", "")
	f.Add("%zz", "")
	hash, err := oauth21.PBKDF2{Iterations: 1}.Hash("secret")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, body, authorization string) {
		m := memstore.New()
		if err := m.AddClient(store.Client{ID: "confidential", Type: store.Confidential, SecretHash: hash}); err != nil {
			t.Fatal(err)
		}
		srv := newServer(t, m, m, m)
		var issued tokenPair
		if strings.Contains(body, "ACCESS") || strings.Contains(body, "REFRESH") {
			issued = tokens(t, srv)
		}
		body = strings.NewReplacer("ACCESS", issued.AccessToken, "REFRESH", issued.RefreshToken).Replace(body)
		r := formRequest("/revoke", body)
		r.Header["Authorization"] = []string{authorization}
		w := do(srv.RevocationHandler(), r)
		if w.Code == http.StatusOK {
			return
		}
		var resp struct{ Error string }
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil || !revocationErrors[resp.Error] {
			t.Fatalf("got status %d, body %+v and error %v", w.Code, resp, err)
		}
		if resp.Error == "invalid_client" && authorization != "" && (w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "") {
			t.Fatalf("got status %d and WWW-Authenticate %q for a failed Authorization header, want 401 with a challenge", w.Code, w.Header().Get("WWW-Authenticate"))
		}
	})
}

// FuzzIntrospectionHandler fuzzes introspection requests in which ACCESS and REFRESH stand for a fresh access token and refresh token of the public Client.
func FuzzIntrospectionHandler(f *testing.F) {
	f.Add("token=ACCESS&client_id=rs&client_secret=secret", "")
	f.Add("token=REFRESH", "Basic cnM6c2VjcmV0")
	f.Add("token=ACCESS&token_type_hint=refresh_token", "Basic cnM6c2VjcmV0")
	f.Add("token=unknown", "Basic cnM6c2VjcmV0")
	f.Add("token=ACCESS&client_id=confidential&client_secret=secret", "")
	f.Add("token=ACCESS&client_id=client", "")
	f.Add("token=ACCESS", "Bearer x")
	f.Add("token=a&token=b", "")
	f.Add("%zz", "")
	hash, err := oauth21.PBKDF2{Iterations: 1}.Hash("secret")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, body, authorization string) {
		m := memstore.New()
		if err := m.AddClient(store.Client{ID: "confidential", Type: store.Confidential, SecretHash: hash}); err != nil {
			t.Fatal(err)
		}
		if err := m.AddClient(store.Client{ID: "rs", Type: store.Confidential, SecretHash: hash, Introspect: true}); err != nil {
			t.Fatal(err)
		}
		srv := newServer(t, m, m, m)
		var issued tokenPair
		if strings.Contains(body, "ACCESS") || strings.Contains(body, "REFRESH") {
			issued = tokens(t, srv)
		}
		body = strings.NewReplacer("ACCESS", issued.AccessToken, "REFRESH", issued.RefreshToken).Replace(body)
		r := formRequest("/introspect", body)
		r.Header["Authorization"] = []string{authorization}
		w := do(srv.IntrospectionHandler(), r)
		var resp map[string]any
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("got status %d and error %v", w.Code, err)
		}
		switch {
		case w.Code == http.StatusOK && resp["active"] == false:
			if len(resp) != 1 {
				t.Fatalf("got %v for an inactive token, want only active false", resp)
			}
		case w.Code == http.StatusOK:
			if resp["active"] != true || resp["client_id"] != "client" || resp["sub"] != "alice" || resp["scope"] != "read" {
				t.Fatalf("got %v, want the access token of alice and client", resp)
			}
		case !introspectionErrors[fmt.Sprint(resp["error"])]:
			t.Fatalf("got status %d and body %v", w.Code, resp)
		case resp["error"] == "invalid_client" && (w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == ""):
			t.Fatalf("got status %d and WWW-Authenticate %q for invalid_client, want 401 with a challenge", w.Code, w.Header().Get("WWW-Authenticate"))
		}
	})
}

func FuzzMetadataHandler(f *testing.F) {
	f.Add(http.MethodGet)
	f.Add(http.MethodHead)
	f.Add(http.MethodPost)
	f.Add("BREW")
	f.Fuzz(func(t *testing.T, method string) {
		m := memstore.New()
		srv := newServer(t, m, m, m)
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://as.example/.well-known/oauth-authorization-server", nil)
		r.Method = method
		w := do(srv.MetadataHandler(), r)
		switch {
		case method == http.MethodGet || method == http.MethodHead:
			var doc map[string]any
			if w.Code != http.StatusOK || json.NewDecoder(w.Body).Decode(&doc) != nil || doc["issuer"] != issuer || doc["token_endpoint"] != issuer+"/token" {
				t.Fatalf("got status %d and body %q, want the metadata of %s", w.Code, w.Body.String(), issuer)
			}
		case w.Code != http.StatusMethodNotAllowed:
			t.Fatalf("got status %d for %s, want 405", w.Code, method)
		}
	})
}

func FuzzNewAcceptsOnlyMountablePaths(f *testing.F) {
	for _, p := range []string{"/token", "/", "/oauth token", "//oauth/token", "/a/../b", "/a/", "/a%20b", "/{a}", "/a?b", "/a#b", "/a?", "/a?b#c", "/a?scope=b", "/a?b=<c>", "/authorize?b", "/.well-known/oauth-authorization-server"} {
		f.Add("", p, "/authorize")
		f.Add(p, "/token", "/authorize")
		f.Add("", "/token", p)
	}
	f.Fuzz(func(t *testing.T, issuerPath, token, authorization string) {
		m := memstore.New()
		srv, err := oauth21.New(oauth21.Config{Issuer: issuer + issuerPath, LoginURL: "/login", Clients: m, AuthorizationRequests: m, Codes: m, Tokens: m, Scopes: readScope, Paths: oauth21.Paths{Authorization: authorization, Token: token}})
		if err != nil {
			return
		}
		p := srv.Paths()
		mux := http.NewServeMux()
		mounts := map[string]http.Handler{
			p.Authorization:    srv.AuthorizationHandler(),
			p.Token:            srv.TokenHandler(),
			p.Revocation:       srv.RevocationHandler(),
			p.Introspection:    srv.IntrospectionHandler(),
			srv.MetadataPath(): srv.MetadataHandler(),
		}
		if len(mounts) != 5 {
			t.Fatalf("got paths %+v and metadata path %q, want them distinct", p, srv.MetadataPath())
		}
		for path, h := range mounts {
			mux.Handle(path, h)
		}
		for path := range mounts {
			if _, pattern := mux.Handler(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://as.example"+path, nil)); pattern != path {
				t.Fatalf("got pattern %q for a request to %q, want it to reach its handler", pattern, path)
			}
		}
	})
}

// newSecureServer returns a server without Clients whose Transport Declaration is secure.
func newSecureServer(t testing.TB, secure func(*http.Request) bool) *oauth21.Server {
	t.Helper()
	m := memstore.New()
	srv, err := oauth21.New(oauth21.Config{
		Issuer:                issuer,
		LoginURL:              "/login",
		Clients:               m,
		AuthorizationRequests: m,
		Codes:                 m,
		Tokens:                m,
		Scopes:                readScope,
		Secure:                secure,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestSecureAsksOnlyWithoutTLS(t *testing.T) {
	var asked []string
	srv := newSecureServer(t, func(r *http.Request) bool {
		asked = append(asked, r.URL.String())
		return true
	})
	legacy := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://legacy.example/.well-known/oauth-authorization-server", nil)
	legacy.TLS.Version = tls.VersionTLS10
	for _, r := range []*http.Request{
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://as.example/.well-known/oauth-authorization-server", nil),
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://as.example/.well-known/oauth-authorization-server", nil),
		legacy,
	} {
		if w := do(srv.MetadataHandler(), r); w.Code != http.StatusOK {
			t.Fatalf("%s: got status %d, want 200", r.URL, w.Code)
		}
	}
	if !slices.Equal(asked, []string{"http://as.example/.well-known/oauth-authorization-server", "https://legacy.example/.well-known/oauth-authorization-server"}) {
		t.Fatalf("got Secure asked for %q, want it asked for the requests without TLS 1.2 only", asked)
	}
}

func TestSecureRefusalIsTLSRequired(t *testing.T) {
	srv := newSecureServer(t, func(*http.Request) bool { return false })
	w := do(srv.MetadataHandler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://as.example/.well-known/oauth-authorization-server", nil))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "TLS required") {
		t.Fatalf("got status %d and body %q, want 400 with TLS required", w.Code, w.Body.String())
	}
}

// countingSecret is acceptSecret counting its verifications.
type countingSecret struct {
	acceptSecret
	verified atomic.Int64
}

func (c *countingSecret) Verify(hash, secret string) bool {
	c.verified.Add(1)
	return c.acceptSecret.Verify(hash, secret)
}

// newLockoutServer returns a Server with the confidential Client "client" and its secret "secret", using hasher, lockout and clock, which may be nil.
func newLockoutServer(t rapid.TB, hasher oauth21.SecretHasher, lockout oauth21.Lockout, clock func() time.Time) *oauth21.Server {
	t.Helper()
	m := memstore.New()
	if err := m.AddClient(store.Client{ID: "client", Type: store.Confidential, AllowedScopes: readScope, DefaultScopes: readScope, SecretHash: "hash", GrantTypes: []string{"client_credentials"}}); err != nil {
		t.Fatal(err)
	}
	srv, err := oauth21.New(oauth21.Config{
		Issuer:                issuer,
		LoginURL:              "/login",
		Clients:               m,
		AuthorizationRequests: m,
		Codes:                 m,
		Tokens:                m,
		Scopes:                readScope,
		SecretHasher:          hasher,
		Lockout:               lockout,
		Clock:                 clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// authenticates reports whether a token request of the Client with secret from the address addr authenticates.
func authenticates(srv *oauth21.Server, secret, addr string) bool {
	r := tokenRequest("grant_type=client_credentials&client_id=client&client_secret=" + secret)
	r.RemoteAddr = addr
	return do(srv.TokenHandler(), r).Code == http.StatusOK
}

// guess sends n token requests of the Client with a wrong secret from addr, each of which must fail.
func guess(t rapid.TB, srv *oauth21.Server, addr string, n int) {
	t.Helper()
	for range n {
		if authenticates(srv, "wrong", addr) {
			t.Fatal("got a wrong secret authenticated")
		}
	}
}

func TestLockoutDefaults(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := newLockoutServer(t, acceptSecret{}, oauth21.Lockout{}, nil)
		guess(t, srv, "[2001:db8::1]:443", 4)
		time.Sleep(15*time.Minute - time.Second)
		guess(t, srv, "[2001:db8::2]:443", 1)
		if authenticates(srv, "secret", "[2001:db8::3]:443") {
			t.Fatal("got the right secret authenticated from a /64 prefix after five failures, want it locked out")
		}
		if !authenticates(srv, "secret", "192.0.2.1:443") {
			t.Fatal("got the right secret refused from another source")
		}
		time.Sleep(15*time.Minute - time.Second)
		if authenticates(srv, "secret", "[2001:db8::1]:443") {
			t.Fatal("got the right secret authenticated before 15 minutes passed, want it locked out")
		}
		time.Sleep(time.Second)
		if !authenticates(srv, "secret", "[2001:db8::1]:443") {
			t.Fatal("got the right secret refused 15 minutes after the last failure")
		}
	})
}

func TestLockoutIsConfigurable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := newLockoutServer(t, acceptSecret{}, oauth21.Lockout{
			Failures: 2,
			Duration: time.Minute,
			Source:   func(*http.Request) string { return "everyone" },
		}, nil)
		guess(t, srv, "192.0.2.1:443", 2)
		if authenticates(srv, "secret", "198.51.100.1:443") {
			t.Fatal("got the right secret authenticated after two failures from the configured source, want it locked out")
		}
		time.Sleep(time.Minute)
		if !authenticates(srv, "secret", "198.51.100.1:443") {
			t.Fatal("got the right secret refused a minute after the last failure")
		}
	})
}

func TestLockoutKeepsFailuresAfterSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := newLockoutServer(t, acceptSecret{}, oauth21.Lockout{}, nil)
		guess(t, srv, "192.0.2.1:443", 4)
		if !authenticates(srv, "secret", "192.0.2.1:443") {
			t.Fatal("got the right secret refused after four failures, want it authenticated")
		}
		guess(t, srv, "192.0.2.1:443", 1)
		if authenticates(srv, "secret", "192.0.2.1:443") {
			t.Fatal("got the right secret authenticated after five failures around a success, want it locked out")
		}
	})
}

// stallSecret is acceptSecret taking ten minutes to verify the secret "stall".
type stallSecret struct {
	acceptSecret
}

func (s stallSecret) Verify(hash, secret string) bool {
	if secret == "stall" {
		time.Sleep(10 * time.Minute)
	}
	return s.acceptSecret.Verify(hash, secret)
}

// stalled returns a Server that locks a source out after two failures, whose Client has from 192.0.2.1 one failure, forgotten in a minute, and one attempt stalled for ten minutes in wg.
func stalled(t *testing.T, wg *sync.WaitGroup) *oauth21.Server {
	t.Helper()
	srv := newLockoutServer(t, stallSecret{}, oauth21.Lockout{Failures: 2, Duration: time.Minute}, nil)
	guess(t, srv, "192.0.2.1:443", 1)
	wg.Go(func() { authenticates(srv, "stall", "192.0.2.1:443") })
	synctest.Wait()
	return srv
}

func TestLockoutWaitEndsWhenFailuresAreForgotten(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var wg sync.WaitGroup
		defer wg.Wait()
		srv := stalled(t, &wg)
		start := time.Now()
		if ok := authenticates(srv, "secret", "192.0.2.1:443"); !ok || time.Since(start) != time.Minute {
			t.Fatalf("got the right secret authenticated %v after %v, want it authenticated after a minute", ok, time.Since(start))
		}
	})
}

func TestLockoutWaitEndsWithRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var wg sync.WaitGroup
		defer wg.Wait()
		srv := stalled(t, &wg)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		r := tokenRequest("grant_type=client_credentials&client_id=client&client_secret=secret").WithContext(ctx)
		r.RemoteAddr = "192.0.2.1:443"
		start := time.Now()
		if w := do(srv.TokenHandler(), r); w.Code == http.StatusOK || time.Since(start) != time.Second {
			t.Fatalf("got status %d after %v for a request canceled after a second, want it refused then", w.Code, time.Since(start))
		}
	})
}

// slowSecret is acceptSecret taking a second to verify, recording how many verifications overlap.
type slowSecret struct {
	acceptSecret
	mu                 sync.Mutex
	verifying, overlap int
}

func (s *slowSecret) Verify(hash, secret string) bool {
	s.mu.Lock()
	s.verifying++
	s.overlap = max(s.overlap, s.verifying)
	s.mu.Unlock()
	time.Sleep(time.Second)
	s.mu.Lock()
	s.verifying--
	s.mu.Unlock()
	return s.acceptSecret.Verify(hash, secret)
}

func TestLockoutSparesConcurrentSuccesses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hasher := &slowSecret{}
		srv := newLockoutServer(t, hasher, oauth21.Lockout{}, nil)
		var refused atomic.Int64
		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() {
				if !authenticates(srv, "secret", "192.0.2.1:443") {
					refused.Add(1)
				}
			})
		}
		wg.Wait()
		if n := refused.Load(); n != 0 || hasher.overlap > 5 {
			t.Fatalf("got %d of 20 concurrent right secrets refused and %d verifications overlapping, want none refused and at most 5", n, hasher.overlap)
		}
	})
}

func TestLockoutLimitsConcurrentGuesses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hasher := &countingSecret{}
		srv := newLockoutServer(t, hasher, oauth21.Lockout{}, nil)
		var wg sync.WaitGroup
		for range 50 {
			wg.Go(func() { authenticates(srv, "wrong", "192.0.2.1:443") })
		}
		wg.Wait()
		if n := hasher.verified.Load(); n != 5 {
			t.Fatalf("got %d secrets verified for 50 concurrent guesses, want 5", n)
		}
	})
}

// TestLockoutModel checks the authentication of a Client from two sources against a model of their failures.
func TestLockoutModel(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		now := time.Unix(1_000_000, 0)
		srv := newLockoutServer(t, acceptSecret{}, oauth21.Lockout{Failures: 3, Duration: time.Minute}, func() time.Time { return now })
		sources := []string{"192.0.2.1:443", "192.0.2.2:443"}
		// failures are the times of the failures of each source since they were last forgotten.
		failures := map[string][]time.Time{}
		lockedOut := func(source string) bool {
			f := failures[source]
			return len(f) >= 3 && now.Sub(f[len(f)-1]) < time.Minute
		}
		t.Repeat(map[string]func(*rapid.T){
			"advance": func(t *rapid.T) {
				now = now.Add(time.Duration(rapid.Int64Range(0, int64(2*time.Minute)).Draw(t, "advance")))
			},
			"wrong": func(t *rapid.T) {
				source := rapid.SampledFrom(sources).Draw(t, "source")
				if authenticates(srv, "wrong", source) {
					t.Fatal("got a wrong secret authenticated")
				}
				if lockedOut(source) {
					return
				}
				if f := failures[source]; len(f) > 0 && now.Sub(f[len(f)-1]) >= time.Minute {
					failures[source] = nil
				}
				failures[source] = append(failures[source], now)
			},
			"right": func(t *rapid.T) {
				source := rapid.SampledFrom(sources).Draw(t, "source")
				want := !lockedOut(source)
				if got := authenticates(srv, "secret", source); got != want {
					t.Fatalf("got the right secret authenticated %v, want %v", got, want)
				}
			},
		})
	})
}
