package memstore_test

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/goleak"

	"github.com/gofabrik/oauth21/memstore"
	"github.com/gofabrik/oauth21/store"
	"github.com/gofabrik/oauth21/storetest"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestEntitiesAreCopied(t *testing.T) {
	m := memstore.New()
	c := store.Client{ID: "client", RedirectURIs: []string{"https://c.example/cb"}, AllowedScopes: []string{"read"}, DefaultScopes: []string{"read"}, GrantTypes: []string{"authorization_code"}, FrameAncestors: []string{"https://portal.example"}}
	m.AddClient(c)
	c.RedirectURIs[0], c.AllowedScopes[0], c.DefaultScopes[0], c.GrantTypes[0], c.FrameAncestors[0] = "https://evil.example/cb", "admin", "admin", "client_credentials", "https://evil.example"
	got, err := m.Client(t.Context(), "client")
	if err != nil {
		t.Fatal(err)
	}
	got.RedirectURIs[0], got.AllowedScopes[0], got.DefaultScopes[0], got.GrantTypes[0], got.FrameAncestors[0] = "https://evil.example/cb", "admin", "admin", "client_credentials", "https://evil.example"
	if again, _ := m.Client(t.Context(), "client"); again.RedirectURIs[0] != "https://c.example/cb" || again.AllowedScopes[0] != "read" || again.DefaultScopes[0] != "read" || again.GrantTypes[0] != "authorization_code" || again.FrameAncestors[0] != "https://portal.example" {
		t.Fatalf("got Client %+v, want the registered one", again)
	}
}

func TestStoreContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) storetest.Store { return memstore.New() })
}

func TestExpiredEntitiesAreRemoved(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := memstore.New()
		expiresAt := time.Now().Add(time.Minute)
		err := errors.Join(
			m.CreateAuthorizationRequest(t.Context(), store.AuthorizationRequest{ID: "expired", ExpiresAt: expiresAt}),
			m.CreateCode(t.Context(), store.Code{Hash: []byte("expired"), ExpiresAt: expiresAt, RetainUntil: expiresAt}),
			m.CreateToken(t.Context(), store.Token{Hash: []byte("expired"), ExpiresAt: expiresAt}),
			m.CreateRefreshToken(t.Context(), store.RefreshToken{Hash: []byte("expired"), ExpiresAt: expiresAt}),
		)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute)
		if err := m.CreateCode(t.Context(), store.Code{Hash: []byte("live"), RetainUntil: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if _, err := m.AuthorizationRequest(t.Context(), "expired"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("got error %v for an expired Authorization Request, want ErrNotFound", err)
		}
		if _, err := m.Code(t.Context(), []byte("expired")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("got error %v for a code past its RetainUntil, want ErrNotFound", err)
		}
		if _, err := m.Token(t.Context(), []byte("expired")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("got error %v for an expired token, want ErrNotFound", err)
		}
		if _, err := m.RefreshToken(t.Context(), []byte("expired")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("got error %v for an expired refresh token, want ErrNotFound", err)
		}
		if _, err := m.Code(t.Context(), []byte("live")); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRemovalFollowsTheClock(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	m := memstore.NewWithClock(func() time.Time { return now })
	for _, r := range []store.AuthorizationRequest{{ID: "expiring", ExpiresAt: now.Add(time.Minute)}, {ID: "pending", ExpiresAt: now.Add(2 * time.Minute)}} {
		if err := m.CreateAuthorizationRequest(t.Context(), r); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(time.Minute)
	if err := m.CreateAuthorizationRequest(t.Context(), store.AuthorizationRequest{ID: "new", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AuthorizationRequest(t.Context(), "expiring"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got error %v for an Authorization Request expired by the clock, want ErrNotFound", err)
	}
	if _, err := m.AuthorizationRequest(t.Context(), "pending"); err != nil {
		t.Fatalf("got error %v for an Authorization Request that has not expired by the clock", err)
	}
}
