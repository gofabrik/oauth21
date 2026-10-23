package conformance

import (
	"testing"
	"time"

	"github.com/gofabrik/oauth21"
)

// TestDeniedRequestRedirectsAccessDenied checks that the Client receives access_denied for a denied Authorization Request.
func TestDeniedRequestRedirectsAccessDenied(t *testing.T) {
	a := newAuthorizationServer(t)
	req := a.pending(a.authorize(authorizeParams()))
	a.wantAuthorizationError(a.deny(req.ID), "access_denied", "")
}

// TestAuthorizationRequestIsSingleUse checks that a completed or denied Authorization Request can be neither completed nor denied again.
func TestAuthorizationRequestIsSingleUse(t *testing.T) {
	for name, first := range map[string]func(*authorizationServer, string){
		"completed": func(a *authorizationServer, id string) { a.complete(id, oauth21.Completion{Subject: "alice"}) },
		"denied":    func(a *authorizationServer, id string) { a.deny(id) },
	} {
		t.Run(name, func(t *testing.T) {
			a := newAuthorizationServer(t)
			req := a.pending(a.authorize(authorizeParams()))
			first(a, req.ID)
			a.wantNotPending(req.ID)
		})
	}
}

// TestAuthorizationRequestExpires checks that an Authorization Request can be neither completed nor denied after its lifetime.
func TestAuthorizationRequestExpires(t *testing.T) {
	a := newAuthorizationServer(t)
	expired := a.pending(a.authorize(authorizeParams()))
	a.advance(9 * time.Minute)
	live := a.pending(a.authorize(authorizeParams()))
	a.advance(time.Minute)
	a.wantNotPending(expired.ID)
	if u := a.complete(live.ID, oauth21.Completion{Subject: "alice"}); u.Query().Get("code") == "" {
		t.Fatalf("got redirect %s, want a code", u)
	}
}

// TestErrorsAfterRedirectURIAreRedirected checks that errors found once the Client and redirect URI are trusted are redirected with error, state and iss.
func TestErrorsAfterRedirectURIAreRedirected(t *testing.T) {
	for responseType, code := range map[string]string{"": "invalid_request", "token": "unsupported_response_type"} {
		t.Run(code, func(t *testing.T) {
			a := newAuthorizationServer(t)
			params := authorizeParams()
			params.Set("response_type", responseType)
			a.wantAuthorizationError(a.authorize(params), code, "response_type")
		})
	}
}
