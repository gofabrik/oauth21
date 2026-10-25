package bearer_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/goleak"

	"github.com/gofabrik/oauth21/bearer"
	"github.com/gofabrik/oauth21/memstore"
	"github.com/gofabrik/oauth21/store"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func sum(v string) []byte {
	s := sha256.Sum256([]byte(v))
	return s[:]
}

// seed stores the access token "token" of alice and client with scope read and audience.
func seed(t testing.TB, m *memstore.Store, audience []string) {
	t.Helper()
	grant := store.Grant{ID: "grant", ClientID: "client", Subject: "alice", Scopes: []string{"read"}, Audience: audience}
	if err := m.CreateToken(context.Background(), store.Token{Hash: sum("token"), Grant: grant, Scopes: grant.Scopes, Audience: audience, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

// protected returns a handler guarded by the middleware with v that requires read and answers with the subject of the token.
func protected(v bearer.Validator) http.Handler {
	return bearer.Middleware(v, "read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := bearer.FromContext(r.Context())
		_, _ = w.Write([]byte(token.Subject))
	}))
}

func request(header string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/resource", nil)
	r.Header.Set("Authorization", header)
	return r
}

func TestLocalChecksAudience(t *testing.T) {
	m := memstore.New()
	seed(t, m, []string{"rs-a"})
	for clientID, want := range map[string]bool{"rs-a": true, "rs-b": false, "": false} {
		token, err := bearer.Local{Tokens: m, ClientID: clientID}.Validate(t.Context(), "token")
		if want && (err != nil || !slices.Equal(token.Audience, []string{"rs-a"})) || !want && !errors.Is(err, bearer.ErrInvalidToken) {
			t.Errorf("%q: got %+v and error %v, want the token only for a Resource Server in its audience", clientID, token, err)
		}
	}
}

func TestLocalTokenExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := memstore.New()
		seed(t, m, nil)
		if _, err := (bearer.Local{Tokens: m}).Validate(t.Context(), "token"); err != nil {
			t.Fatalf("got error %v before expiry, want the token", err)
		}
		time.Sleep(time.Hour)
		if _, err := (bearer.Local{Tokens: m}).Validate(t.Context(), "token"); !errors.Is(err, bearer.ErrInvalidToken) {
			t.Fatalf("got error %v at expiry, want ErrInvalidToken", err)
		}
	})
}

func TestHandlerGetsAudience(t *testing.T) {
	m := memstore.New()
	seed(t, m, []string{"rs-a"})
	var got bearer.Token
	h := bearer.Middleware(bearer.Local{Tokens: m, ClientID: "rs-a"})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = bearer.FromContext(r.Context())
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request("Bearer token"))
	if w.Code != http.StatusOK || got.Subject != "alice" || !slices.Equal(got.Audience, []string{"rs-a"}) {
		t.Fatalf("got status %d and token %+v, want 200 and the token of alice with audience rs-a", w.Code, got)
	}
}

// remote returns a Remote for an introspection endpoint that answers every request with status and body.
func remote(t *testing.T, status int, body string) bearer.Remote {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return bearer.Remote{Endpoint: ts.URL, ClientID: "rs-a", ClientSecret: "secret", Client: ts.Client()}
}

func TestRemoteReturnsToken(t *testing.T) {
	r := remote(t, http.StatusOK, `{"active":true,"scope":"read write","client_id":"client","sub":"alice","exp":1419356238,"aud":["rs-a"]}`)
	got, err := r.Validate(t.Context(), "token")
	want := bearer.Token{Subject: "alice", ClientID: "client", Scopes: []string{"read", "write"}, Audience: []string{"rs-a"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v and error %v, want %+v", got, err, want)
	}
}

func TestRemoteMalformedResponseIsServerError(t *testing.T) {
	for _, body := range []string{`{"active":"true"}`, `[]`, ``} {
		w := httptest.NewRecorder()
		protected(remote(t, http.StatusOK, body)).ServeHTTP(w, request("Bearer token"))
		if w.Code != http.StatusInternalServerError || w.Header().Get("WWW-Authenticate") != "" {
			t.Errorf("%q: got status %d and WWW-Authenticate %q, want 500 without a challenge", body, w.Code, w.Header().Get("WWW-Authenticate"))
		}
	}
}

// blockingTransport answers no request until it is canceled.
type blockingTransport struct{}

func (blockingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, r.Context().Err()
}

func TestRemoteTimesOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &http.Client{Transport: blockingTransport{}, Timeout: time.Second}
		w := httptest.NewRecorder()
		protected(bearer.Remote{Endpoint: "https://as.example/introspect", Client: client}).ServeHTTP(w, request("Bearer token"))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("got status %d, want 500 when introspection times out", w.Code)
		}
	})
}

type failingTokens struct{ store.Tokens }

func (failingTokens) Token(context.Context, []byte) (store.Token, error) {
	return store.Token{}, errors.New("unavailable")
}

func TestStoreFailureIsServerError(t *testing.T) {
	w := httptest.NewRecorder()
	protected(bearer.Local{Tokens: failingTokens{}}).ServeHTTP(w, request("Bearer token"))
	if w.Code != http.StatusInternalServerError || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("got status %d and WWW-Authenticate %q, want 500 without a challenge", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}

func TestMiddlewareRequiresScopeTokens(t *testing.T) {
	for _, scope := range []string{"", "a b", `a"b`, `a\b`} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%q: got no panic, want one for a malformed scope", scope)
				}
			}()
			bearer.Middleware(bearer.Local{}, "read", scope)
		}()
	}
}

func FuzzMiddleware(f *testing.F) {
	f.Add("Bearer token")
	f.Add("bearer token")
	f.Add("Bearer other")
	f.Add("Bearer")
	f.Add("Basic eDp5")
	f.Fuzz(func(t *testing.T, header string) {
		m := memstore.New()
		seed(t, m, nil)
		w := httptest.NewRecorder()
		r := request("")
		r.Header["Authorization"] = []string{header}
		protected(bearer.Local{Tokens: m}).ServeHTTP(w, r)
		challenge := w.Header().Get("WWW-Authenticate")
		switch w.Code {
		case http.StatusOK:
			if w.Body.String() != "alice" || challenge != "" {
				t.Fatalf("got body %q and WWW-Authenticate %q, want alice without a challenge", w.Body.String(), challenge)
			}
		case http.StatusBadRequest, http.StatusUnauthorized:
			if !strings.HasPrefix(challenge, `Bearer realm="oauth21", scope="read"`) {
				t.Fatalf("got status %d and WWW-Authenticate %q, want a Bearer challenge", w.Code, challenge)
			}
		default:
			t.Fatalf("got status %d for %q, want 200, 400 or 401", w.Code, header)
		}
	})
}
