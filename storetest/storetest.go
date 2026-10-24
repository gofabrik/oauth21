// Package storetest checks a Store against the contract of the store interfaces.
package storetest

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gofabrik/oauth21/store"
)

// Store is the set of Store interfaces Run checks.
type Store interface {
	store.AuthorizationRequests
	store.Codes
	store.Tokens
}

// concurrency is the number of goroutines racing for one entity.
const concurrency = 8

// Run checks the Stores that newStore returns, one empty Store per test, each reading the time with time.Now.
func Run(t *testing.T, newStore func(t *testing.T) Store) {
	t.Run("CodeIsSingleUse", func(t *testing.T) { testCodeIsSingleUse(t, newStore(t)) })
	t.Run("ConcurrentConsumeCode", func(t *testing.T) { testConcurrentConsumeCode(t, newStore(t)) })
	t.Run("ConcurrentConsumeAuthorizationRequest", func(t *testing.T) { testConcurrentConsumeAuthorizationRequest(t, newStore(t)) })
	t.Run("RevokeGrant", func(t *testing.T) { testRevokeGrant(t, newStore(t)) })
	t.Run("ConcurrentRevokeGrant", func(t *testing.T) { testConcurrentRevokeGrant(t, newStore(t)) })
	t.Run("Expiry", func(t *testing.T) { testExpiry(t, newStore(t)) })
	t.Run("UsedCodeIsRetained", func(t *testing.T) { testUsedCodeIsRetained(t, newStore(t)) })
	t.Run("EntitiesAreCopied", func(t *testing.T) { testEntitiesAreCopied(t, newStore(t)) })
}

func newCode(hash string, expiresAt time.Time) store.Code {
	return store.Code{
		Hash:                []byte(hash),
		Grant:               store.Grant{ID: "grant-" + hash, ClientID: "client", Subject: "alice", Scopes: []string{"read"}, Audience: []string{"api"}},
		RedirectURI:         "https://client.example/cb",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		ExpiresAt:           expiresAt,
		RetainUntil:         expiresAt.Add(time.Hour),
	}
}

// sameCode reports whether a and b are equal, comparing times to the second.
func sameCode(a, b store.Code) bool {
	if !sameTime(a.ExpiresAt, b.ExpiresAt) || !sameTime(a.RetainUntil, b.RetainUntil) {
		return false
	}
	a.ExpiresAt, a.RetainUntil = b.ExpiresAt, b.RetainUntil
	return reflect.DeepEqual(a, b)
}

func sameTime(a, b time.Time) bool {
	return a.Truncate(time.Second).Equal(b.Truncate(time.Second))
}

func testCodeIsSingleUse(t *testing.T, s Store) {
	ctx := t.Context()
	want := newCode("code", time.Now().Add(time.Minute))
	if err := s.CreateCode(ctx, want); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Code(ctx, want.Hash); err != nil || !sameCode(got, want) {
		t.Fatalf("Code returned %+v and error %v, want %+v", got, err, want)
	}
	if got, err := s.ConsumeCode(ctx, want.Hash); err != nil || !sameCode(got, want) {
		t.Fatalf("first ConsumeCode returned %+v and error %v, want the unused code %+v", got, err, want)
	}
	want.Used = true
	if got, err := s.ConsumeCode(ctx, want.Hash); err != nil || !sameCode(got, want) {
		t.Fatalf("second ConsumeCode returned %+v and error %v, want the used code %+v", got, err, want)
	}
	if got, err := s.Code(ctx, want.Hash); err != nil || !sameCode(got, want) {
		t.Fatalf("Code of a consumed code returned %+v and error %v, want the used code %+v", got, err, want)
	}
	for name, op := range map[string]func(context.Context, []byte) (store.Code, error){"Code": s.Code, "ConsumeCode": s.ConsumeCode} {
		if _, err := op(ctx, []byte("unknown")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s of an unknown code returned error %v, want ErrNotFound", name, err)
		}
	}
}

func testConcurrentConsumeCode(t *testing.T, s Store) {
	c := newCode("code", time.Now().Add(time.Minute))
	if err := s.CreateCode(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	unused := race(t, concurrency, func(int) (bool, error) {
		got, err := s.ConsumeCode(t.Context(), c.Hash)
		return !got.Used, err
	})
	if unused != 1 {
		t.Fatalf("%d concurrent ConsumeCode calls returned the code unused, want 1", unused)
	}
}

func testConcurrentConsumeAuthorizationRequest(t *testing.T, s Store) {
	r := store.AuthorizationRequest{ID: "request", ClientID: "client", Scopes: []string{"read"}, ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.CreateAuthorizationRequest(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	consumed := race(t, concurrency, func(int) (bool, error) {
		_, err := s.ConsumeAuthorizationRequest(t.Context(), r.ID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return true, err
	})
	if consumed != 1 {
		t.Fatalf("%d concurrent ConsumeAuthorizationRequest calls succeeded, want 1", consumed)
	}
	if _, err := s.AuthorizationRequest(t.Context(), r.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("AuthorizationRequest of a consumed request returned error %v, want ErrNotFound", err)
	}
}

// race runs op n times concurrently, passing each call its index, and returns how many calls won.
func race(t *testing.T, n int, op func(i int) (won bool, err error)) int {
	t.Helper()
	start := make(chan struct{})
	won := make([]bool, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() {
			<-start
			won[i], errs[i] = op(i)
		})
	}
	close(start)
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	wins := 0
	for _, w := range won {
		if w {
			wins++
		}
	}
	return wins
}

func newToken(hash, grantID string) store.Token {
	return store.Token{Hash: []byte(hash), Grant: store.Grant{ID: grantID, ClientID: "client"}, Audience: []string{"api"}, ExpiresAt: time.Now().Add(time.Hour)}
}

func testRevokeGrant(t *testing.T, s Store) {
	ctx := t.Context()
	for _, tok := range []store.Token{newToken("a", "revoked"), newToken("b", "revoked"), newToken("c", "other")} {
		if err := s.CreateToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RevokeGrant(ctx, "revoked"); err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{"a", "b"} {
		if _, err := s.Token(ctx, []byte(hash)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Token of a revoked Grant returned error %v, want ErrNotFound", err)
		}
	}
	if err := s.CreateToken(ctx, newToken("d", "revoked")); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("CreateToken for a revoked Grant returned error %v, want ErrRevoked", err)
	}
	if _, err := s.Token(ctx, []byte("c")); err != nil {
		t.Fatalf("Token of another Grant returned error %v", err)
	}
	if err := s.RevokeGrant(ctx, "unknown"); err != nil {
		t.Fatalf("RevokeGrant of a Grant without tokens returned error %v", err)
	}
	if err := s.CreateToken(ctx, newToken("e", "unknown")); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("CreateToken for a Grant revoked before its first token returned error %v, want ErrRevoked", err)
	}
}

func testConcurrentRevokeGrant(t *testing.T, s Store) {
	ctx := t.Context()
	race(t, concurrency+1, func(i int) (bool, error) {
		if i == 0 {
			return true, s.RevokeGrant(ctx, "grant")
		}
		err := s.CreateToken(ctx, newToken(strconv.Itoa(i), "grant"))
		if errors.Is(err, store.ErrRevoked) {
			return false, nil
		}
		return true, err
	})
	for i := 1; i <= concurrency; i++ {
		if _, err := s.Token(ctx, []byte(strconv.Itoa(i))); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Token created while its Grant was revoked returned error %v, want ErrNotFound", err)
		}
	}
}

func testExpiry(t *testing.T, s Store) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		c := newCode("code", time.Now().Add(time.Minute))
		r := store.AuthorizationRequest{ID: "request", ClientID: "client", ExpiresAt: c.ExpiresAt}
		tok := newToken("token", "grant")
		tok.ExpiresAt = c.ExpiresAt
		if err := errors.Join(s.CreateCode(ctx, c), s.CreateAuthorizationRequest(ctx, r), s.CreateToken(ctx, tok)); err != nil {
			t.Fatal(err)
		}
		advance(t, s, time.Minute-time.Nanosecond)
		if got, err := s.AuthorizationRequest(ctx, r.ID); err != nil || !sameTime(got.ExpiresAt, r.ExpiresAt) {
			t.Fatalf("AuthorizationRequest returned %+v and error %v before expiry, want the request", got, err)
		}
		if got, err := s.Token(ctx, tok.Hash); err != nil || !sameTime(got.ExpiresAt, tok.ExpiresAt) {
			t.Fatalf("Token returned %+v and error %v before expiry, want the token", got, err)
		}
		advance(t, s, time.Nanosecond)
		if got, err := s.AuthorizationRequest(ctx, r.ID); err == nil && !sameTime(got.ExpiresAt, r.ExpiresAt) || err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("AuthorizationRequest returned %+v and error %v after expiry, want the request or ErrNotFound", got, err)
		}
		if got, err := s.Token(ctx, tok.Hash); err == nil && !sameTime(got.ExpiresAt, tok.ExpiresAt) || err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Token returned %+v and error %v after expiry, want the token or ErrNotFound", got, err)
		}
		advance(t, s, time.Hour-time.Nanosecond)
		if got, err := s.Code(ctx, c.Hash); err != nil || !sameCode(got, c) {
			t.Fatalf("Code returned %+v and error %v before RetainUntil, want the code", got, err)
		}
		advance(t, s, time.Nanosecond)
		if got, err := s.Code(ctx, c.Hash); err == nil && !sameCode(got, c) || err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Code returned %+v and error %v after RetainUntil, want the code or ErrNotFound", got, err)
		}
	})
}

func testUsedCodeIsRetained(t *testing.T, s Store) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		c := newCode("code", time.Now().Add(time.Minute))
		if err := s.CreateCode(ctx, c); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ConsumeCode(ctx, c.Hash); err != nil {
			t.Fatal(err)
		}
		advance(t, s, time.Until(c.RetainUntil)-time.Nanosecond)
		if got, err := s.Code(ctx, c.Hash); err != nil || !got.Used {
			t.Fatalf("Code returned %+v and error %v for a used code before RetainUntil, want the used code", got, err)
		}
	})
}

// advance sleeps for d and then creates one entity of each kind.
func advance(t *testing.T, s Store, d time.Duration) {
	t.Helper()
	time.Sleep(d)
	now := strconv.FormatInt(time.Now().UnixNano(), 10)
	err := errors.Join(
		s.CreateAuthorizationRequest(t.Context(), store.AuthorizationRequest{ID: "later-" + now, ExpiresAt: time.Now().Add(time.Minute)}),
		s.CreateCode(t.Context(), newCode("later-"+now, time.Now().Add(time.Minute))),
		s.CreateToken(t.Context(), newToken("later-"+now, "later-"+now)),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func testEntitiesAreCopied(t *testing.T, s Store) {
	ctx := t.Context()
	r := store.AuthorizationRequest{ID: "request", Scopes: []string{"read"}, ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.CreateAuthorizationRequest(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Scopes[0] = "admin"
	if got, err := s.AuthorizationRequest(ctx, r.ID); err != nil || got.Scopes[0] != "read" {
		t.Fatalf("AuthorizationRequest returned %+v and error %v after the created request changed, want scope read", got, err)
	}

	c := newCode("code", time.Now().Add(time.Minute))
	if err := s.CreateCode(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.Hash[0], c.Grant.Scopes[0], c.Grant.Audience[0] = 'x', "admin", "other"
	for name, op := range map[string]func(context.Context, []byte) (store.Code, error){"ConsumeCode": s.ConsumeCode, "Code": s.Code} {
		got, err := op(ctx, []byte("code"))
		if err != nil || got.Grant.Scopes[0] != "read" || got.Grant.Audience[0] != "api" {
			t.Fatalf("%s returned %+v and error %v after a code changed, want the stored one", name, got, err)
		}
		got.Grant.Scopes[0], got.Grant.Audience[0] = "admin", "other"
	}
	if got, err := s.Code(ctx, []byte("code")); err != nil || got.Grant.Scopes[0] != "read" || got.Grant.Audience[0] != "api" {
		t.Fatalf("Code returned %+v and error %v after returned codes changed, want the stored one", got, err)
	}
}
