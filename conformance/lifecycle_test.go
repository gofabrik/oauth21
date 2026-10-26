package conformance

import (
	"errors"
	"strconv"
	"sync"
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
//
//conformance:covers INV-0009
func TestAuthorizationRequestIsSingleUse(t *testing.T) {
	for name, first := range map[string]func(*authorizationServer, string){
		"completed": func(a *authorizationServer, id string) {
			a.complete(id, oauth21.Completion{Subject: "alice", Scopes: readScope})
		},
		"denied": func(a *authorizationServer, id string) { a.deny(id) },
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
//
//conformance:covers INV-0011
func TestAuthorizationRequestExpires(t *testing.T) {
	a := newAuthorizationServer(t)
	expired := a.pending(a.authorize(authorizeParams()))
	a.advance(9 * time.Minute)
	live := a.pending(a.authorize(authorizeParams()))
	a.advance(time.Minute)
	a.wantNotPending(expired.ID)
	if u := a.complete(live.ID, oauth21.Completion{Subject: "alice", Scopes: readScope}); u.Query().Get("code") == "" {
		t.Fatalf("got redirect %s, want a code", u)
	}
}

// TestConcurrentCompletionAndDenialSucceedOnce checks that of concurrent completions and denials of one Authorization Request exactly one succeeds, also when every completion has read the request as pending before any denial.
//
//conformance:covers INV-0010
func TestConcurrentCompletionAndDenialSucceedOnce(t *testing.T) {
	a := newAuthorizationServer(t)
	req := a.pending(a.authorize(authorizeParams()))
	a.recorder.barrier.hold(concurrentRequests)
	defer a.recorder.barrier.hold(0)
	start := make(chan struct{})
	errs := make([]error, concurrentRequests)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() {
			<-start
			if i%2 == 0 {
				_, errs[i] = a.srv.Complete(t.Context(), req.ID, oauth21.Completion{Subject: "alice", Scopes: readScope})
			} else {
				// A denial does not load the request, so it joins the round of the completions here.
				a.recorder.barrier.arrive()
				_, errs[i] = a.srv.Deny(t.Context(), req.ID)
			}
		})
	}
	close(start)
	wg.Wait()
	succeeded := 0
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case !errors.Is(err, oauth21.ErrRequestNotPending):
			t.Fatalf("got error %v, want ErrRequestNotPending", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("got %d successful completions and denials, want 1", succeeded)
	}
}

// TestErrorsAfterRedirectURIAreRedirected checks that errors found once the Client and redirect URI are trusted are redirected with error, state and iss.
//
//conformance:covers OAUTH21D16-4.1.1-03
func TestErrorsAfterRedirectURIAreRedirected(t *testing.T) {
	for responseType, code := range map[string]string{"": "invalid_request", "token": "unsupported_response_type", "code token": "unsupported_response_type", "code id_token": "unsupported_response_type", "CODE": "unsupported_response_type"} {
		t.Run(strconv.Quote(responseType), func(t *testing.T) {
			a := newAuthorizationServer(t)
			params := authorizeParams()
			params.Set("response_type", responseType)
			a.wantAuthorizationError(a.authorize(params), code, "response_type")
		})
	}
}
