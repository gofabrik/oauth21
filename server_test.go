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
	"pgregory.net/rapid"

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
func requestID(t rapid.TB, srv *oauth21.Server) string {
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
		"short request lifetime":      func(c *oauth21.Config) { c.AuthorizationRequestLifetime = time.Millisecond },
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
		if w.Code >= 500 || w.Code != http.StatusFound && w.Header().Get("Location") != "" {
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

// FuzzTokenHandler fuzzes token requests in which CODE stands for a freshly issued code.
func FuzzTokenHandler(f *testing.F) {
	f.Add(tokenBody("CODE"), "")
	f.Add(tokenBody("CODE")+"&code=other", "")
	f.Add(strings.Replace(tokenBody("CODE"), "dBjf", "xBjf", 1), "")
	f.Add(tokenBody("CODE")+"&client_secret=s", "")
	f.Add(strings.Replace(tokenBody("CODE"), "client_id=client", "client_id=confidential&client_secret=secret", 1), "")
	f.Add(tokenBody("CODE"), "Basic Y29uZmlkZW50aWFsOnNlY3JldA==")
	f.Add(tokenBody("CODE"), "Basic !")
	f.Add(tokenBody("CODE"), "Bearer x")
	f.Add("grant_type=client_credentials", "")
	f.Add("%zz", "")
	hash, err := oauth21.PBKDF2{Iterations: 1}.Hash("secret")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, body, authorization string) {
		m := memstore.New()
		m.AddClient(store.Client{ID: "confidential", Type: store.Confidential, RedirectURIs: []string{"https://client.example/cb"}, SecretHash: hash})
		srv := newServer(t, m, m, m)
		body = strings.ReplaceAll(body, "CODE", issueCode(t, srv))
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
	m.AddClient(store.Client{ID: "client", Type: store.Confidential, RedirectURIs: []string{"https://client.example/cb"}, SecretHash: "hash"})
	srv, err := oauth21.New(oauth21.Config{
		Issuer:                issuer,
		LoginURL:              "/login",
		Clients:               m,
		AuthorizationRequests: m,
		Codes:                 m,
		Tokens:                m,
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

// failingStores fails the Client and Authorization Request Stores when set.
type failingStores struct {
	*memstore.Store
	clients, requests bool
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

func TestUntrustedErrorsAreRendered(t *testing.T) {
	tests := map[string]struct {
		query  string
		stores failingStores
		status int
		code   string
	}{
		"unknown client":       {strings.Replace(authorizeQuery, "client_id=client", "client_id=other", 1), failingStores{}, http.StatusBadRequest, "invalid_request"},
		"repeated parameter":   {authorizeQuery + "&client_id=client", failingStores{}, http.StatusBadRequest, "invalid_request"},
		"client Store failure": {authorizeQuery, failingStores{clients: true}, http.StatusInternalServerError, "server_error"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := tt.stores
			f.Store = memstore.New()
			f.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}})
			var got oauth21.AuthorizationError
			srv, err := oauth21.New(oauth21.Config{
				Issuer:                issuer,
				LoginURL:              "/login",
				Clients:               &f,
				AuthorizationRequests: &f,
				Codes:                 f.Store,
				Tokens:                f.Store,
				RenderError: func(w http.ResponseWriter, _ *http.Request, e oauth21.AuthorizationError) {
					got = e
					w.WriteHeader(http.StatusTeapot)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			w := do(srv.AuthorizationHandler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/authorize?"+tt.query, nil))
			if w.Code != http.StatusTeapot || got.Status != tt.status || got.Code != tt.code {
				t.Fatalf("got status %d and rendered error %+v, want the renderer called with %d and %q", w.Code, got, tt.status, tt.code)
			}
		})
	}
}

func TestStoreFailureAfterTrustIsRedirected(t *testing.T) {
	f := &failingStores{Store: memstore.New(), requests: true}
	f.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}})
	srv, err := oauth21.New(oauth21.Config{Issuer: issuer, LoginURL: "/login", Clients: f, AuthorizationRequests: f, Codes: f, Tokens: f})
	if err != nil {
		t.Fatal(err)
	}
	w := do(srv.AuthorizationHandler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/authorize?"+authorizeQuery, nil))
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if w.Code != http.StatusFound || loc.Host != "client.example" || q.Get("error") != "server_error" || q.Get("state") != "xyz" || q.Get("iss") != issuer || q.Has("error_description") {
		t.Fatalf("got status %d and Location %s, want a server_error redirect to the Client with state and iss only", w.Code, loc)
	}
}

func TestConcurrentCompletionAndDenialSucceedOnce(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	id := requestID(t, srv)

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			if i%2 == 0 {
				_, errs[i] = srv.Complete(t.Context(), id, oauth21.Completion{Subject: "alice"})
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
		expired := requestID(t, srv)
		time.Sleep(10*time.Minute - time.Second)
		live := requestID(t, srv)
		time.Sleep(time.Second)
		if _, err := srv.Complete(t.Context(), expired, oauth21.Completion{Subject: "alice"}); !errors.Is(err, oauth21.ErrRequestNotPending) {
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

// TestAuthorizationRequestLifecycle checks Authorization Requests against a model of pending requests and their expiry.
func TestAuthorizationRequestLifecycle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		now := time.Unix(1_000_000, 0)
		m := memstore.New()
		m.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{"https://client.example/cb"}})
		srv, err := oauth21.New(oauth21.Config{
			Issuer:                       issuer,
			LoginURL:                     "/login",
			Clients:                      m,
			AuthorizationRequests:        m,
			Codes:                        m,
			Tokens:                       m,
			AuthorizationRequestLifetime: time.Minute,
			Clock:                        func() time.Time { return now },
		})
		if err != nil {
			t.Fatal(err)
		}
		pending := map[string]time.Time{}
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
				id := requestID(t, srv)
				pending[id] = now.Add(time.Minute)
				ids = append(ids, id)
			},
			"advance": func(t *rapid.T) {
				now = now.Add(time.Duration(rapid.Int64Range(0, int64(time.Minute)).Draw(t, "advance")))
			},
			"read": func(t *rapid.T) {
				id, want := draw(t)
				_, err := srv.AuthorizationRequest(context.Background(), id)
				wantPending(t, err, want)
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
				redirect, err := srv.Complete(context.Background(), id, oauth21.Completion{Subject: "alice"})
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
				if want && !strings.Contains(redirect, "error=access_denied") {
					t.Fatalf("got redirect %q, want access_denied", redirect)
				}
				delete(pending, id)
			},
		})
	})
}

func TestEmptyRegisteredRedirectURIIsRendered(t *testing.T) {
	m := memstore.New()
	srv := newServer(t, m, m, m)
	m.AddClient(store.Client{ID: "client", Type: store.Public, RedirectURIs: []string{""}})
	w := do(srv.AuthorizationHandler(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/authorize?"+authorizeQuery, nil))
	if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Fatalf("got status %d and Location %q, want 400 without redirect", w.Code, w.Header().Get("Location"))
	}
}
