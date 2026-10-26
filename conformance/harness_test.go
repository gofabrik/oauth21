package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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
	mux      *http.ServeMux
	client   *http.Client
	skew     atomic.Int64
	recorder *recorder
}

// recorder records the keys and entities the Authorization Server sends to the code and token Stores, and holds its loads of codes and refresh tokens at barrier.
type recorder struct {
	*memstore.Store
	mu       sync.Mutex
	received [][]byte
	// entities are the codes and tokens the Stores received, formatted with their field names.
	entities []string
	barrier  barrier
}

// barrier makes loads wait in rounds until all loads of a round have arrived.
type barrier struct {
	mu sync.Mutex
	// racers is the number of loads in each round; 0 lets every load pass.
	racers int
	// held is the number of loads still to arrive in the current round.
	held int
	// loaded is closed when the current round is complete.
	loaded chan struct{}
}

func (r *recorder) record(key []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.received = append(r.received, slices.Clone(key))
}

func (r *recorder) recordEntity(e any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entities = append(r.entities, fmt.Sprintf("%+v", e))
}

// hold makes loads wait in rounds of n until all n of a round have arrived; hold(0) lets every load pass.
func (b *barrier) hold(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.racers, b.held, b.loaded = n, n, make(chan struct{})
}

// arrive waits until all loads of its round have arrived, or for at most five seconds.
func (b *barrier) arrive() {
	b.mu.Lock()
	if b.racers == 0 {
		b.mu.Unlock()
		return
	}
	b.held--
	loaded := b.loaded
	if b.held == 0 {
		close(loaded)
		b.held, b.loaded = b.racers, make(chan struct{})
	}
	b.mu.Unlock()
	select {
	case <-loaded:
	case <-time.After(5 * time.Second):
	}
}

func (r *recorder) CreateCode(ctx context.Context, c store.Code) error {
	r.record(c.Hash)
	r.recordEntity(c)
	return r.Store.CreateCode(ctx, c)
}

func (r *recorder) Code(ctx context.Context, hash []byte) (store.Code, error) {
	r.record(hash)
	defer r.barrier.arrive()
	return r.Store.Code(ctx, hash)
}

func (r *recorder) ConsumeCode(ctx context.Context, hash []byte) (store.Code, error) {
	r.record(hash)
	return r.Store.ConsumeCode(ctx, hash)
}

func (r *recorder) CreateToken(ctx context.Context, t store.Token) error {
	r.record(t.Hash)
	r.recordEntity(t)
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
	r.recordEntity(t)
	return r.Store.CreateRefreshToken(ctx, t)
}

func (r *recorder) RefreshToken(ctx context.Context, hash []byte) (store.RefreshToken, error) {
	r.record(hash)
	defer r.barrier.arrive()
	return r.Store.RefreshToken(ctx, hash)
}

func (r *recorder) RotateRefreshToken(ctx context.Context, hash []byte, next store.RefreshToken) (store.RefreshToken, error) {
	r.record(hash)
	r.record(next.Hash)
	r.recordEntity(next)
	return r.Store.RotateRefreshToken(ctx, hash, next)
}

// keys returns the keys recorded so far.
func (r *recorder) keys() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.received)
}

// recorded returns the entities recorded so far, formatted with their field names.
func (r *recorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.entities)
}

// publicClient returns a public Client with redirectURIs that is allowed and defaults to scope read.
func publicClient(id string, redirectURIs ...string) store.Client {
	return store.Client{ID: id, Type: store.Public, RedirectURIs: redirectURIs, AllowedScopes: readScope, DefaultScopes: readScope}
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
	a.url, a.mux, a.client, a.recorder = ts.URL, mux, ts.Client(), &recorder{Store: m}
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

// seededRandom is a deterministic randomness source: the SHA-256 counter stream of its seed, with one bit inverted when flip is set.
type seededRandom struct {
	mu   sync.Mutex
	seed byte
	// flip is the bit of the stream to invert, counted from 1; 0 inverts none.
	flip    int
	counter uint64
	buf     []byte
	read    int
}

func (s *seededRandom) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) < len(p) {
		block := sha256.Sum256(binary.BigEndian.AppendUint64([]byte{s.seed}, s.counter))
		s.counter++
		s.buf = append(s.buf, block[:]...)
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	if bit := s.flip - 1; bit >= 0 && bit/8 >= s.read && bit/8 < s.read+n {
		p[bit/8-s.read] ^= 1 << (bit % 8)
	}
	s.read += n
	return n, nil
}

// bytesRead returns how many bytes were read from s so far.
func (s *seededRandom) bytesRead() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read
}

// newSeededServer starts an Authorization Server with randomness source s, the public Client and any extra Clients.
func newSeededServer(t *testing.T, s *seededRandom, clients ...store.Client) *authorizationServer {
	t.Helper()
	return newConfiguredServer(t, func(c *oauth21.Config) { c.Random = s }, clients...)
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
	return a.redirect(header.Get("Location"))
}

// redirect parses the redirect location loc and checks that no parameter of its query is repeated.
func (a *authorizationServer) redirect(loc string) *url.URL {
	a.t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		a.t.Fatal(err)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		a.t.Fatal(err)
	}
	for name, values := range q {
		if len(values) > 1 {
			a.t.Fatalf("got redirect %s with %s repeated, want each parameter once", loc, name)
		}
	}
	return u
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
	return a.redirect(redirect)
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
	if _, err := members(raw); err != nil {
		a.t.Fatalf("got body %s: %v", raw, err)
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
	return a.redirect(redirect)
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

// members returns the member names of the JSON object raw in order, and fails for anything else, including a repeated member name.
func members(raw []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	var names []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := tok.(string)
		if slices.Contains(names, name) {
			return nil, fmt.Errorf("repeated member %q", name)
		}
		names = append(names, name)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
	}
	return names, nil
}
