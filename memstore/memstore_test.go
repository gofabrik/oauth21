package memstore_test

import (
	"errors"
	"testing"

	"go.uber.org/goleak"

	"github.com/gofabrik/oauth21/memstore"
	"github.com/gofabrik/oauth21/store"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestEntitiesAreCopied(t *testing.T) {
	m := memstore.New()
	c := store.Client{ID: "client", RedirectURIs: []string{"https://c.example/cb"}}
	m.AddClient(c)
	c.RedirectURIs[0] = "https://evil.example/cb"
	got, err := m.Client(t.Context(), "client")
	if err != nil {
		t.Fatal(err)
	}
	got.RedirectURIs[0] = "https://evil.example/cb"
	if again, _ := m.Client(t.Context(), "client"); again.RedirectURIs[0] != "https://c.example/cb" {
		t.Fatalf("got redirect URI %q, want the registered one", again.RedirectURIs[0])
	}

	r := store.AuthorizationRequest{ID: "r", Scopes: []string{"read"}}
	if err := m.CreateAuthorizationRequest(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	r.Scopes[0] = "admin"
	if got, _ := m.AuthorizationRequest(t.Context(), "r"); got.Scopes[0] != "read" {
		t.Fatalf("got scope %q, want read", got.Scopes[0])
	}

	code := store.Code{Hash: []byte("h"), Grant: store.Grant{Scopes: []string{"read"}, Audience: []string{"api"}}}
	if err := m.CreateCode(t.Context(), code); err != nil {
		t.Fatal(err)
	}
	code.Hash[0], code.Grant.Scopes[0], code.Grant.Audience[0] = 'x', "admin", "other"
	got2, err := m.ConsumeCode(t.Context(), []byte("h"))
	if err != nil || got2.Grant.Scopes[0] != "read" || got2.Grant.Audience[0] != "api" {
		t.Fatalf("got code %+v and error %v, want the stored one", got2, err)
	}
}

func TestRevokedGrantRefusesTokens(t *testing.T) {
	m := memstore.New()
	grant := store.Grant{ID: "g"}
	if err := m.CreateToken(t.Context(), store.Token{Hash: []byte("a"), Grant: grant}); err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeGrant(t.Context(), "g"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Token(t.Context(), []byte("a")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got error %v for a token of a revoked Grant, want ErrNotFound", err)
	}
	if err := m.CreateToken(t.Context(), store.Token{Hash: []byte("b"), Grant: grant}); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("got error %v creating a token for a revoked Grant, want ErrRevoked", err)
	}
}
