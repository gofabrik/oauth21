package conformance

import (
	"maps"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/gofabrik/oauth21"
)

// aliceCompletion completes an Authorization Request as alice, granting scope read.
func aliceCompletion() oauth21.Completion {
	return oauth21.Completion{Subject: "alice", Scopes: readScope}
}

// wantAwaitsResourceOwner sends the authorization request params, checks that it reaches the login URL without a code as a pending Authorization Request other than the seen ones, and returns its identifier.
func (a *authorizationServer) wantAwaitsResourceOwner(params url.Values, seen ...string) string {
	a.t.Helper()
	loc := a.authorize(params)
	if loc.Query().Has("code") {
		a.t.Fatalf("got redirect %s, want no code before the Resource Owner completes the request", loc)
	}
	id := a.pending(loc).ID
	if slices.Contains(seen, id) {
		a.t.Fatalf("got Authorization Request %q again, want a new one", id)
	}
	return id
}

// TestAuthorizationRequestAwaitsResourceOwner checks that a valid authorization request issues no code until the Host Application completes it.
//
//conformance:covers OAUTH21D16-7.3.1-01
func TestAuthorizationRequestAwaitsResourceOwner(t *testing.T) {
	a := newAuthorizationServer(t)
	id := a.wantAwaitsResourceOwner(authorizeParams())
	if u := a.complete(id, aliceCompletion()); u.Query().Get("code") == "" {
		t.Fatalf("got redirect %s, want a code once completed", u)
	}
}

// newRequest returns params with a new state and code challenge, as a Client sends for another authorization.
func newRequest(params url.Values) url.Values {
	params = maps.Clone(params)
	params.Set("state", "abc")
	params.Set("code_challenge", s256(verifier+"-next"))
	return params
}

// TestRepeatedAuthorizationRequestAwaitsResourceOwner checks that replaying a completed authorization request with the same parameters makes a new pending Authorization Request.
//
//conformance:covers OAUTH21D16-7.3-02
func TestRepeatedAuthorizationRequestAwaitsResourceOwner(t *testing.T) {
	a := newAuthorizationServer(t)
	first := a.wantAwaitsResourceOwner(authorizeParams())
	a.complete(first, aliceCompletion())
	a.wantAwaitsResourceOwner(authorizeParams(), first)
}

// TestApprovedClientAwaitsResourceOwner checks that an authorization request of a Client the Resource Owner approved before goes to the login URL again.
//
//conformance:covers OAUTH21D16-7.3.1-02
func TestApprovedClientAwaitsResourceOwner(t *testing.T) {
	a := newAuthorizationServer(t)
	first := a.wantAwaitsResourceOwner(authorizeParams())
	a.complete(first, aliceCompletion())
	a.wantAwaitsResourceOwner(newRequest(authorizeParams()), first)
}

// TestDeniedRequestIssuesNoCode checks that a Client gets no code for an authorization request the Resource Owner denied, and cannot get one for it later.
//
//conformance:covers RFC6749-10.12-06
func TestDeniedRequestIssuesNoCode(t *testing.T) {
	a := newAuthorizationServer(t)
	id := a.wantAwaitsResourceOwner(authorizeParams())
	if u := a.deny(id); u.Query().Has("code") || u.Query().Get("error") != "access_denied" {
		t.Fatalf("got redirect %s, want access_denied without a code", u)
	}
	a.wantNotPending(id)
}

// TestNativeAppRequestAwaitsResourceOwner checks that a native app's authorization request issues no code until the Host Application completes it.
//
//conformance:covers RFC8252-8.6-01
func TestNativeAppRequestAwaitsResourceOwner(t *testing.T) {
	a := newAuthorizationServer(t, nativeClient())
	id := a.wantAwaitsResourceOwner(nativeParams())
	if u := a.complete(id, aliceCompletion()); u.Query().Get("code") == "" {
		t.Fatalf("got redirect %s, want a code once completed", u)
	}
}

// TestApprovedNativeAppAwaitsResourceOwner checks that an authorization request of a native app the Resource Owner approved before goes to the login URL again.
//
//conformance:covers RFC8252-8.6-02
func TestApprovedNativeAppAwaitsResourceOwner(t *testing.T) {
	a := newAuthorizationServer(t, nativeClient())
	first := a.wantAwaitsResourceOwner(nativeParams())
	a.complete(first, aliceCompletion())
	a.wantAwaitsResourceOwner(newRequest(nativeParams()), first)
}

// TestPendingRequestDescribesAuthorization checks that the Host Application sees the Client, the requested scopes and how long the Grant lasts.
//
//conformance:covers OAUTH21D16-7.3-03
func TestPendingRequestDescribesAuthorization(t *testing.T) {
	codeOnly := publicClient("code only", redirectURI)
	codeOnly.GrantTypes = []string{"authorization_code"}
	const access, refresh = 2 * time.Hour, 48 * time.Hour
	a := newConfiguredServer(t, func(c *oauth21.Config) { c.AccessTokenLifetime, c.RefreshTokenLifetime = access, refresh }, codeOnly)
	params := authorizeParams()
	params.Set("scope", "read write")
	req := a.pending(a.authorize(params))
	if req.Client.ID != clientID || !slices.Equal(req.Scopes, []string{"read", "write"}) || req.Lifetime != refresh {
		t.Fatalf("got %+v, want the public Client, scopes read and write and the refresh token lifetime", req)
	}
	params.Set("client_id", "code only")
	params.Set("scope", "read")
	if req := a.pending(a.authorize(params)); req.Client.ID != "code only" || req.Lifetime != access {
		t.Fatalf("got %+v, want the Client without refresh tokens and the access token lifetime", req)
	}
}

// TestPendingRequestNamesClientAndDeveloper checks that the Host Application sees the Client's name and developer with the requested scopes.
//
//conformance:covers OAUTH21D16-7.9-03
func TestPendingRequestNamesClientAndDeveloper(t *testing.T) {
	named := publicClient("named", redirectURI)
	named.Name, named.Developer = "Photo Printer", "Example Prints Ltd"
	a := newAuthorizationServer(t, named)
	params := authorizeParams()
	params.Set("client_id", "named")
	req := a.pending(a.authorize(params))
	if req.Client.Name != "Photo Printer" || req.Client.Developer != "Example Prints Ltd" || !slices.Equal(req.Scopes, readScope) {
		t.Fatalf("got %+v, want the Client's name and developer and scope read", req)
	}
}
