package conformance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
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
	clientID    = "public-client"
	redirectURI = "https://client.example/cb"
	verifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	state       = "xyz"
)

// readScope is the scope most Clients under test are allowed and default to.
var readScope = []string{"read"}

// challenge is the S256 code challenge of verifier.
var challenge = s256(verifier)

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorizationServer is an Authorization Server under test, reached over HTTP.
type authorizationServer struct {
	t        *testing.T
	srv      *oauth21.Server
	url      string
	client   *http.Client
	skew     atomic.Int64
	recorder *recorder
}

// recorder records the keys the Authorization Server sends to the code and token Stores.
type recorder struct {
	*memstore.Store
	mu       sync.Mutex
	received [][]byte
}

func (r *recorder) record(key []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.received = append(r.received, slices.Clone(key))
}

func (r *recorder) CreateCode(ctx context.Context, c store.Code) error {
	r.record(c.Hash)
	return r.Store.CreateCode(ctx, c)
}

func (r *recorder) Code(ctx context.Context, hash []byte) (store.Code, error) {
	r.record(hash)
	return r.Store.Code(ctx, hash)
}

func (r *recorder) ConsumeCode(ctx context.Context, hash []byte) (store.Code, error) {
	r.record(hash)
	return r.Store.ConsumeCode(ctx, hash)
}

func (r *recorder) CreateToken(ctx context.Context, t store.Token) error {
	r.record(t.Hash)
	return r.Store.CreateToken(ctx, t)
}

func (r *recorder) Token(ctx context.Context, hash []byte) (store.Token, error) {
	r.record(hash)
	return r.Store.Token(ctx, hash)
}

func (r *recorder) RevokeToken(ctx context.Context, hash []byte) error {
	r.record(hash)
	return r.Store.RevokeToken(ctx, hash)
}

func (r *recorder) CreateRefreshToken(ctx context.Context, t store.RefreshToken) error {
	r.record(t.Hash)
	return r.Store.CreateRefreshToken(ctx, t)
}

func (r *recorder) RefreshToken(ctx context.Context, hash []byte) (store.RefreshToken, error) {
	r.record(hash)
	return r.Store.RefreshToken(ctx, hash)
}

func (r *recorder) RotateRefreshToken(ctx context.Context, hash []byte, next store.RefreshToken) (store.RefreshToken, error) {
	r.record(hash)
	r.record(next.Hash)
	return r.Store.RotateRefreshToken(ctx, hash, next)
}

// keys returns the keys recorded so far.
func (r *recorder) keys() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.received)
}

// newAuthorizationServer starts an Authorization Server with the public Client and any extra Clients.
func newAuthorizationServer(t *testing.T, clients ...store.Client) *authorizationServer {
	t.Helper()
	return newConfiguredServer(t, func(*oauth21.Config) {}, clients...)
}

// newConfiguredServer starts an Authorization Server with the Config that configure changes, the public Client and any extra Clients.
func newConfiguredServer(t *testing.T, configure func(*oauth21.Config), clients ...store.Client) *authorizationServer {
	t.Helper()
	a := &authorizationServer{t: t}
	m := memstore.NewWithClock(a.now)
	m.AddClient(store.Client{ID: clientID, Type: store.Public, RedirectURIs: []string{redirectURI}, AllowedScopes: []string{"read", "write"}, DefaultScopes: readScope})
	for _, c := range clients {
		m.AddClient(c)
	}
	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	a.url, a.client, a.recorder = ts.URL, ts.Client(), &recorder{Store: m}
	a.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.Cleanup(a.client.CloseIdleConnections)
	c := oauth21.Config{
		Issuer:                ts.URL,
		LoginURL:              ts.URL + "/login",
		Clients:               m,
		AuthorizationRequests: m,
		Codes:                 a.recorder,
		Tokens:                a.recorder,
		Scopes:                []string{"read", "write", "admin"},
		Clock:                 a.now,
	}
	configure(&c)
	srv, err := oauth21.New(c)
	if err != nil {
		t.Fatal(err)
	}
	a.srv = srv
	paths := srv.Paths()
	mux.Handle(paths.Authorization, srv.AuthorizationHandler())
	mux.Handle(paths.Token, srv.TokenHandler())
	mux.Handle(paths.Revocation, srv.RevocationHandler())
	mux.Handle(paths.Introspection, srv.IntrospectionHandler())
	mux.Handle(srv.MetadataPath(), srv.MetadataHandler())
	return a
}

// now is the clock of the Authorization Server and its Stores.
func (a *authorizationServer) now() time.Time {
	return time.Now().Add(time.Duration(a.skew.Load()))
}

// advance moves the clock of the Authorization Server forward by d.
func (a *authorizationServer) advance(d time.Duration) {
	a.skew.Add(int64(d))
}

// authorizeParams returns a valid authorization request for the public Client.
func authorizeParams() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
}

// send sends a request with header to path and returns the status, headers and body of the response.
func (a *authorizationServer) send(method, path, form string, header http.Header) (int, http.Header, []byte) {
	a.t.Helper()
	req, err := http.NewRequestWithContext(a.t.Context(), method, a.url+path, strings.NewReader(form))
	if err != nil {
		a.t.Fatal(err)
	}
	if header != nil {
		req.Header = header.Clone()
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err := errors.Join(err, resp.Body.Close()); err != nil {
		a.t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, body
}

// authorize sends an authorization request and returns the redirect location.
func (a *authorizationServer) authorize(params url.Values) *url.URL {
	a.t.Helper()
	status, header, _ := a.send(http.MethodGet, "/authorize?"+params.Encode(), "", nil)
	if status != http.StatusFound {
		a.t.Fatalf("got status %d, want a redirect", status)
	}
	loc, err := url.Parse(header.Get("Location"))
	if err != nil {
		a.t.Fatal(err)
	}
	return loc
}

// login completes the Authorization Request at loc as subject, granting the requested scopes.
func (a *authorizationServer) login(loc *url.URL, subject string) *url.URL {
	a.t.Helper()
	req := a.pending(loc)
	return a.complete(req.ID, oauth21.Completion{Subject: subject, Scopes: req.Scopes})
}

// pending follows the redirect to the login URL and returns the pending Authorization Request.
func (a *authorizationServer) pending(loc *url.URL) oauth21.AuthorizationRequest {
	a.t.Helper()
	if got := endpoint(loc); got != a.url+"/login" {
		a.t.Fatalf("got redirect to %s, want the login URL", loc)
	}
	req, err := a.srv.AuthorizationRequest(a.t.Context(), loc.Query().Get("request_id"))
	if err != nil {
		a.t.Fatal(err)
	}
	return req
}

// complete completes the Authorization Request id with c and returns the redirect to the Client.
func (a *authorizationServer) complete(id string, c oauth21.Completion) *url.URL {
	a.t.Helper()
	redirect, err := a.srv.Complete(a.t.Context(), id, c)
	if err != nil {
		a.t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		a.t.Fatal(err)
	}
	return u
}

// code runs an authorization request through login and returns the code it issues.
func (a *authorizationServer) code(params url.Values) string {
	a.t.Helper()
	u := a.login(a.authorize(params), "alice")
	code := u.Query().Get("code")
	if code == "" {
		a.t.Fatalf("got redirect %s, want a code", u)
	}
	return code
}

// tokenParams returns a valid token request for code.
func tokenParams(code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
}

// withVerifier returns a copy of params with code_verifier set to v, or removed when v is empty.
func withVerifier(params url.Values, v string) url.Values {
	p := maps.Clone(params)
	p.Del("code_verifier")
	if v != "" {
		p.Set("code_verifier", v)
	}
	return p
}

// token sends a token request with header and returns the status, headers and decoded JSON body.
func (a *authorizationServer) token(params url.Values, header http.Header) (int, http.Header, map[string]any) {
	a.t.Helper()
	return a.sendJSON(http.MethodPost, "/token", params.Encode(), header)
}

// sendJSON sends a request with header to path and returns the status, headers and decoded JSON body of the response.
func (a *authorizationServer) sendJSON(method, path, form string, header http.Header) (int, http.Header, map[string]any) {
	a.t.Helper()
	status, respHeader, raw := a.send(method, path, form, header)
	if ct := respHeader.Get("Content-Type"); ct != "application/json" {
		a.t.Fatalf("got Content-Type %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		a.t.Fatal(err)
	}
	return status, respHeader, body
}

// wantOAuthError checks that a token, revocation or introspection endpoint error response has wantStatus and carries code.
func (a *authorizationServer) wantOAuthError(status int, body map[string]any, wantStatus int, code string) {
	t := a.t
	t.Helper()
	if status != wantStatus || body["error"] != code {
		t.Fatalf("got status %d and body %v, want %d and error %q", status, body, wantStatus, code)
	}
}

// wantAuthorizationError checks that loc is an authorization error response with code and description.
func (a *authorizationServer) wantAuthorizationError(loc *url.URL, code, description string) {
	t := a.t
	t.Helper()
	q := loc.Query()
	if got := endpoint(loc); got != redirectURI {
		t.Fatalf("got redirect to %s, want %s", got, redirectURI)
	}
	if q.Get("error") != code || q.Get("state") != state || q.Get("iss") != a.url || q.Has("code") {
		t.Fatalf("got redirect %s, want error %q with state and iss", loc, code)
	}
	if !strings.Contains(q.Get("error_description"), description) {
		t.Fatalf("got error_description %q, want it to contain %q", q.Get("error_description"), description)
	}
}

// endpoint returns u without its query.
func endpoint(u *url.URL) string {
	return u.Scheme + "://" + u.Host + u.Path
}

// deny denies the Authorization Request id and returns the redirect to the Client.
func (a *authorizationServer) deny(id string) *url.URL {
	a.t.Helper()
	redirect, err := a.srv.Deny(a.t.Context(), id)
	if err != nil {
		a.t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		a.t.Fatal(err)
	}
	return u
}

// wantNotPending checks that the Authorization Request id can be neither read, completed nor denied.
func (a *authorizationServer) wantNotPending(id string) {
	t := a.t
	t.Helper()
	if _, err := a.srv.AuthorizationRequest(t.Context(), id); !errors.Is(err, oauth21.ErrRequestNotPending) {
		t.Fatalf("got error %v reading the request, want ErrRequestNotPending", err)
	}
	if _, err := a.srv.Complete(t.Context(), id, oauth21.Completion{Subject: "alice", Scopes: readScope}); !errors.Is(err, oauth21.ErrRequestNotPending) {
		t.Fatalf("got error %v completing the request, want ErrRequestNotPending", err)
	}
	if _, err := a.srv.Deny(t.Context(), id); !errors.Is(err, oauth21.ErrRequestNotPending) {
		t.Fatalf("got error %v denying the request, want ErrRequestNotPending", err)
	}
}
