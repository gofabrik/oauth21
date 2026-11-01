package conformance

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gofabrik/oauth21"
)

// sourceHeader names the source of a request to the Authorization Servers of these tests.
const sourceHeader = "X-Test-Source"

// newLockoutServer starts an Authorization Server with the introspection Clients that locks out a source after three failed authentications of a Client for a minute.
func newLockoutServer(t *testing.T) *authorizationServer {
	t.Helper()
	return newConfiguredServer(t, func(c *oauth21.Config) {
		c.Lockout = oauth21.Lockout{
			Failures: 3,
			Duration: time.Minute,
			Source:   func(r *http.Request) string { return r.Header.Get(sourceHeader) },
		}
	}, newIntrospectionClients(t)...)
}

// secretEndpoint is an endpoint that authenticates Clients with their secret.
type secretEndpoint struct {
	path   string
	client string
	form   url.Values
	// accepted is the status of a request that authenticates.
	accepted int
}

var secretEndpoints = map[string]secretEndpoint{
	"token":         {"/token", confidentialID, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"unknown"}}, http.StatusBadRequest},
	"revocation":    {"/revoke", confidentialID, url.Values{"token": {"unknown"}}, http.StatusOK},
	"introspection": {"/introspect", resourceServerID, url.Values{"token": {"unknown"}}, http.StatusOK},
}

// authenticate sends the request of e with the Client's secret from source and returns the status and body of the response.
func (a *authorizationServer) authenticate(e secretEndpoint, secret, source string) (int, []byte) {
	a.t.Helper()
	header := basic(e.client, secret)
	header.Set(sourceHeader, source)
	status, _, body := a.send(http.MethodPost, e.path, e.form.Encode(), header)
	return status, body
}

// guess sends n requests of e with a wrong secret from source, each of which must fail authentication.
func (a *authorizationServer) guess(e secretEndpoint, source string, n int) {
	a.t.Helper()
	for range n {
		if status, body := a.authenticate(e, "wrong", source); status != http.StatusUnauthorized {
			a.t.Fatalf("got status %d and body %s for a wrong secret, want 401", status, body)
		}
	}
}

// TestSecretEndpointsLockOutGuessing checks that the token, revocation and introspection endpoints refuse even the right secret from a source that failed to authenticate the Client too often.
//
//conformance:covers OAUTH21D16-2.4.1-06
func TestSecretEndpointsLockOutGuessing(t *testing.T) {
	for name, e := range secretEndpoints {
		t.Run(name, func(t *testing.T) {
			a := newLockoutServer(t)
			a.guess(e, "attacker", 3)
			if status, body := a.authenticate(e, secret, "attacker"); status != http.StatusUnauthorized {
				t.Fatalf("got status %d and body %s for the right secret after three failures, want 401", status, body)
			}
		})
	}
}

// TestGuessesOfClientSecretAreLimited checks that a source is refused the right secret after three wrong guesses, also with a success among them, that this refusal looks like a wrong guess, and that it lasts a minute after the last wrong guess.
//
//conformance:covers OAUTH21D16-7.7-06
func TestGuessesOfClientSecretAreLimited(t *testing.T) {
	e := secretEndpoints["token"]
	a := newLockoutServer(t)
	_, wrong := a.authenticate(e, "wrong", "attacker")
	a.guess(e, "attacker", 1)
	if status, body := a.authenticate(e, secret, "attacker"); status != e.accepted {
		t.Fatalf("got status %d and body %s for the right third guess, want %d", status, body, e.accepted)
	}
	a.guess(e, "attacker", 1)
	if status, body := a.authenticate(e, secret, "attacker"); status != http.StatusUnauthorized || !bytes.Equal(body, wrong) {
		t.Fatalf("got status %d and body %s for the right secret after three failures, want 401 and %s", status, body, wrong)
	}
	a.advance(time.Minute - time.Second)
	if status, body := a.authenticate(e, secret, "attacker"); status != http.StatusUnauthorized {
		t.Fatalf("got status %d and body %s for the right secret before the minute passed, want 401", status, body)
	}
	a.advance(time.Second)
	if status, body := a.authenticate(e, secret, "attacker"); status != e.accepted {
		t.Fatalf("got status %d and body %s for the right secret after the minute, want %d", status, body, e.accepted)
	}
}

// TestLockoutSparesOtherSources checks that a source locked out for a Client does not lock out the Client from another source.
//
//conformance:covers INV-0017
func TestLockoutSparesOtherSources(t *testing.T) {
	for name, e := range secretEndpoints {
		t.Run(name, func(t *testing.T) {
			a := newLockoutServer(t)
			a.guess(e, "attacker", 10)
			if status, body := a.authenticate(e, secret, "client"); status != e.accepted {
				t.Fatalf("got status %d and body %s from another source, want %d", status, body, e.accepted)
			}
		})
	}
}
