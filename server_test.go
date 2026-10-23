package oauth21_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/goleak"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/memstore"
	"github.com/gofabrik/oauth21/store"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

const (
	issuer   = "https://as.example"
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func sum(v string) []byte {
	s := sha256.Sum256([]byte(v))
	return s[:]
}

// recorder records the keys the Authorization Server sends to the code and token Stores.
type recorder struct {
	*memstore.Store
	keys [][]byte
}

func (r *recorder) CreateCode(ctx context.Context, c store.Code) error {
	r.keys = append(r.keys, c.Hash)
	return r.Store.CreateCode(ctx, c)
}

func (r *recorder) Code(ctx context.Context, hash []byte) (store.Code, error) {
	r.keys = append(r.keys, hash)
	return r.Store.Code(ctx, hash)
}

func (r *recorder) ConsumeCode(ctx context.Context, hash []byte) (store.Code, error) {
	r.keys = append(r.keys, hash)
	return r.Store.ConsumeCode(ctx, hash)
}

func (r *recorder) CreateToken(ctx context.Context, t store.Token) error {
	r.keys = append(r.keys, t.Hash)
	return r.Store.CreateToken(ctx, t)
}

func newServer(t testing.TB, m *memstore.Store, codes store.Codes, tokens store.Tokens) *oauth21.Server {
	t.Helper()
	m.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}})
	srv, err := oauth21.New(oauth21.Config{
		Issuer:                issuer,
		LoginURL:              "/login",
		Clients:               m,
		AuthorizationRequests: m,
		Codes:                 codes,
		Tokens:                tokens,
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
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestStoresOnlyReceiveHashes(t *testing.T) {
	m := memstore.New()
	rec := &recorder{Store: m}
	srv := newServer(t, m, rec, rec)

	code := issueCode(t, srv)

	token := accessToken(t, do(srv.TokenHandler(), tokenRequest(tokenBody(code))))

	want := [][]byte{sum(code), sum(code), sum(code), sum(token)}
	if len(rec.keys) != len(want) {
		t.Fatalf("got %d Store keys, want %d", len(rec.keys), len(want))
	}
	for i, key := range rec.keys {
		if !bytes.Equal(key, want[i]) {
			t.Errorf("Store key %d is %x, want the SHA-256 hash %x", i, key, want[i])
		}
	}
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

// requestID sends an authorization request and returns the identifier of the pending Authorization Request.
func requestID(t testing.TB, srv *oauth21.Server) string {
	t.Helper()
	loc, err := url.Parse(do(srv.AuthorizationHandler(), httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+authorizeQuery, nil)).Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query().Get("request_id")
}

// issueCode runs an authorization request through Complete and returns the code.
func issueCode(t testing.TB, srv *oauth21.Server) string {
	t.Helper()
	redirect, err := srv.Complete(context.Background(), requestID(t, srv), oauth21.Completion{Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	cb, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	return cb.Query().Get("code")
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

func TestNewRequiresConfig(t *testing.T) {
	m := memstore.New()
	valid := oauth21.Config{
		Issuer:                issuer,
		LoginURL:              "/login",
		Clients:               m,
		AuthorizationRequests: m,
		Codes:                 m,
		Tokens:                m,
	}
	for name, change := range map[string]func(*oauth21.Config){
		"issuer":                      func(c *oauth21.Config) { c.Issuer = "" },
		"http issuer":                 func(c *oauth21.Config) { c.Issuer = "http://as.example" },
		"relative issuer":             func(c *oauth21.Config) { c.Issuer = "as.example" },
		"issuer with query":           func(c *oauth21.Config) { c.Issuer = "https://as.example?tenant=a" },
		"issuer with fragment":        func(c *oauth21.Config) { c.Issuer = "https://as.example#a" },
		"negative code lifetime":      func(c *oauth21.Config) { c.CodeLifetime = -time.Second },
		"long code lifetime":          func(c *oauth21.Config) { c.CodeLifetime = 11 * time.Minute },
		"negative token lifetime":     func(c *oauth21.Config) { c.AccessTokenLifetime = -time.Second },
		"short code lifetime":         func(c *oauth21.Config) { c.CodeLifetime = time.Millisecond },
		"short token lifetime":        func(c *oauth21.Config) { c.AccessTokenLifetime = 500 * time.Millisecond },
		"malformed login URL":         func(c *oauth21.Config) { c.LoginURL = "%zz" },
		"login URL":                   func(c *oauth21.Config) { c.LoginURL = "" },
		"client Store":                func(c *oauth21.Config) { c.Clients = nil },
		"Authorization Request Store": func(c *oauth21.Config) { c.AuthorizationRequests = nil },
		"code Store":                  func(c *oauth21.Config) { c.Codes = nil },
		"token Store":                 func(c *oauth21.Config) { c.Tokens = nil },
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

func FuzzAuthorizationHandler(f *testing.F) {
	f.Add(false, authorizeQuery)
	f.Add(true, authorizeQuery)
	f.Add(false, authorizeQuery+"&client_id=client")
	f.Add(false, strings.Replace(authorizeQuery, "S256", "plain", 1))
	f.Add(false, "client_id=%zz&redirect_uri=http://127.0.0.1:1/cb")
	m := memstore.New()
	h := newServer(f, m, m, m).AuthorizationHandler()
	f.Fuzz(func(t *testing.T, post bool, params string) {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize", nil)
		r.URL.RawQuery = params
		if post {
			r = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/authorize", strings.NewReader(params))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		w := do(h, r)
		if w.Code >= 500 {
			t.Fatalf("got status %d", w.Code)
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

// FuzzTokenHandler fuzzes token requests in which CODE stands for a freshly issued code.
func FuzzTokenHandler(f *testing.F) {
	f.Add(tokenBody("CODE"))
	f.Add(tokenBody("CODE") + "&code=other")
	f.Add(strings.Replace(tokenBody("CODE"), "dBjf", "xBjf", 1))
	f.Add(tokenBody("CODE") + "&client_secret=s")
	f.Add("grant_type=client_credentials")
	f.Add("%zz")
	f.Fuzz(func(t *testing.T, body string) {
		m := memstore.New()
		srv := newServer(t, m, m, m)
		body = strings.ReplaceAll(body, "CODE", issueCode(t, srv))
		w := do(srv.TokenHandler(), tokenRequest(body))
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
	})
}
