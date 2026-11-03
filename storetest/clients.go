package storetest

import (
	"errors"
	"strconv"
	"testing"

	"github.com/gofabrik/oauth21/store"
)

// Clients is the Clients Store RunClients checks, with the registration of Clients.
type Clients interface {
	store.Clients
	// AddClient registers c and fails when its Resource is not a Resource URI or belongs to another Client.
	AddClient(c store.Client) error
}

// RunClients checks the Clients Stores that newClients returns, one empty Store per test.
func RunClients(t *testing.T, newClients func(t *testing.T) Clients) {
	t.Run("ResourceServer", func(t *testing.T) { testResourceServer(t, newClients(t)) })
	t.Run("ResourceURIBelongsToOneClient", func(t *testing.T) { testResourceURIBelongsToOneClient(t, newClients(t)) })
	t.Run("ResourceURIComparesSchemeAndHostInAnyCase", func(t *testing.T) { testResourceURIComparesSchemeAndHostInAnyCase(t, newClients(t)) })
	t.Run("ResourceMustBeResourceURI", func(t *testing.T) { testResourceMustBeResourceURI(t, newClients(t)) })
	t.Run("ConcurrentAddClient", func(t *testing.T) { testConcurrentAddClient(t, newClients(t)) })
}

const resourceURI = "https://rs.example/api"

func addClients(t *testing.T, s Clients, clients ...store.Client) {
	t.Helper()
	for _, c := range clients {
		if err := s.AddClient(c); err != nil {
			t.Fatal(err)
		}
	}
}

// wantResourceServer checks that the Resource URI uri belongs to the Client id.
func wantResourceServer(t *testing.T, s Clients, uri, id string) {
	t.Helper()
	if got, err := s.ResourceServer(t.Context(), uri); err != nil || got.ID != id || got.Resource != uri {
		t.Fatalf("ResourceServer(%q) returned %+v and error %v, want the Client %q", uri, got, err, id)
	}
}

func testResourceServer(t *testing.T, s Clients) {
	addClients(t, s, store.Client{ID: "rs", Type: store.Confidential, Resource: resourceURI}, store.Client{ID: "client", Type: store.Public}, store.Client{ID: "other", Type: store.Public})
	wantResourceServer(t, s, resourceURI, "rs")
	for _, uri := range []string{"", "https://rs.example/API", "https://rs.example/api/", "https://rs.example", "https://rs.example/ap", "rs"} {
		if got, err := s.ResourceServer(t.Context(), uri); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("ResourceServer(%q) returned %+v and error %v, want ErrNotFound", uri, got, err)
		}
	}
}

func testResourceURIBelongsToOneClient(t *testing.T, s Clients) {
	rs := store.Client{ID: "rs", Type: store.Confidential, Resource: resourceURI}
	addClients(t, s, rs)
	if err := s.AddClient(store.Client{ID: "other", Type: store.Confidential, Resource: resourceURI}); err == nil {
		t.Fatal("AddClient of a second Client with the Resource URI succeeded, want an error")
	}
	wantResourceServer(t, s, resourceURI, "rs")
	if _, err := s.Client(t.Context(), "other"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Client of the refused Client returned error %v, want ErrNotFound", err)
	}
	addClients(t, s, rs)
	rs.Resource = "https://rs.example/v2"
	addClients(t, s, rs, store.Client{ID: "other", Type: store.Confidential, Resource: resourceURI})
	wantResourceServer(t, s, resourceURI, "other")
	wantResourceServer(t, s, rs.Resource, "rs")
}

func testResourceURIComparesSchemeAndHostInAnyCase(t *testing.T, s Clients) {
	addClients(t, s, store.Client{ID: "rs", Type: store.Confidential, Resource: "HTTPS://RS.Example/api"})
	wantResourceServer(t, s, resourceURI, "rs")
	if got, err := s.ResourceServer(t.Context(), "Https://rs.EXAMPLE/api"); err != nil || got.ID != "rs" || got.Resource != resourceURI {
		t.Fatalf("ResourceServer of the Resource URI in another case returned %+v and error %v, want the Client rs", got, err)
	}
	if err := s.AddClient(store.Client{ID: "other", Type: store.Confidential, Resource: resourceURI}); err == nil {
		t.Fatal("AddClient of a second Client with the Resource URI in another case succeeded, want an error")
	}
}

func testResourceMustBeResourceURI(t *testing.T, s Clients) {
	for _, uri := range []string{"rs", "/api", resourceURI + "?v=1", resourceURI + "#v1", "https://rs.example/a b"} {
		if err := s.AddClient(store.Client{ID: "rs", Type: store.Confidential, Resource: uri}); err == nil {
			t.Fatalf("AddClient with Resource %q succeeded, want an error", uri)
		}
	}
}

func testConcurrentAddClient(t *testing.T, s Clients) {
	added := race(t, concurrency, func(i int) (bool, error) {
		return s.AddClient(store.Client{ID: "rs-" + strconv.Itoa(i), Type: store.Confidential, Resource: resourceURI}) == nil, nil
	})
	if added != 1 {
		t.Fatalf("%d concurrent AddClient calls with the same Resource URI succeeded, want 1", added)
	}
}
