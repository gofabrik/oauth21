package conformance

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/store"
)

// authorizationResponseHeaders returns the headers of every kind of authorization endpoint response for the Client clientID.
func (a *authorizationServer) authorizationResponseHeaders(clientID string) []http.Header {
	a.t.Helper()
	valid, unsupported := authorizeParams(), unsupportedParams()
	valid.Set("client_id", clientID)
	unsupported.Set("client_id", clientID)
	var headers []http.Header
	for _, params := range []url.Values{valid, unsupported, unknownClientParams()} {
		_, h, _ := a.send(http.MethodGet, "/authorize?"+params.Encode(), "", nil)
		headers = append(headers, h)
	}
	a.overPlainHTTP(func() {
		_, h, _ := a.send(http.MethodGet, "/authorize?"+valid.Encode(), "", nil)
		headers = append(headers, h)
	})
	return headers
}

// frameAncestors returns the sources of the frame-ancestors directive in the Content-Security-Policy of h, and whether there is one.
func frameAncestors(h http.Header) ([]string, bool) {
	for _, policy := range h.Values("Content-Security-Policy") {
		for directive := range strings.SplitSeq(policy, ";") {
			name, sources, _ := strings.Cut(strings.TrimSpace(directive), " ")
			if strings.EqualFold(name, "frame-ancestors") {
				return strings.Fields(sources), true
			}
		}
	}
	return nil, false
}

// wantNoFrameAncestors checks that the Content-Security-Policy of h has a frame-ancestors directive that allows no origin.
func wantNoFrameAncestors(t *testing.T, h http.Header) {
	t.Helper()
	if sources, ok := frameAncestors(h); !ok || !slices.Equal(sources, []string{"'none'"}) {
		t.Fatalf("got Content-Security-Policy %q, want frame-ancestors 'none'", h.Values("Content-Security-Policy"))
	}
}

// wantDenyFrameOptions checks that h carries X-Frame-Options DENY.
func wantDenyFrameOptions(t *testing.T, h http.Header) {
	t.Helper()
	if got := h.Values("X-Frame-Options"); !slices.Equal(got, []string{"DENY"}) {
		t.Fatalf("got X-Frame-Options %q, want DENY", got)
	}
}

// wantNoFraming checks that h lets no origin frame the response, with Content-Security-Policy and with X-Frame-Options.
func wantNoFraming(t *testing.T, h http.Header) {
	t.Helper()
	wantNoFrameAncestors(t, h)
	wantDenyFrameOptions(t, h)
}

// TestAuthorizationEndpointCannotBeFramed checks that no origin can frame a response of the authorization endpoint: a redirect to the login URL, a redirected error, an error page or the refusal of plain HTTP.
//
//conformance:covers OAUTH21D16-7.11-01
func TestAuthorizationEndpointCannotBeFramed(t *testing.T) {
	for _, h := range newAuthorizationServer(t).authorizationResponseHeaders(clientID) {
		wantNoFrameAncestors(t, h)
	}
}

// newFramingServer starts an Authorization Server with the Clients whose Host Application protects its login page with ProtectFraming and the Client's FrameAncestors.
func newFramingServer(t *testing.T, clients ...store.Client) *authorizationServer {
	t.Helper()
	a := newAuthorizationServer(t, clients...)
	a.mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		req, err := a.srv.AuthorizationRequest(r.Context(), r.FormValue("request_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		oauth21.ProtectFraming(w.Header(), req.Client.FrameAncestors...)
	})
	return a
}

// loginPageHeaders follows the redirect of the authorization request for clientID to the login page and returns the headers of the page.
func (a *authorizationServer) loginPageHeaders(clientID string) http.Header {
	a.t.Helper()
	params := authorizeParams()
	params.Set("client_id", clientID)
	loc := a.authorize(params)
	status, h, body := a.send(http.MethodGet, loc.RequestURI(), "", nil)
	if status != http.StatusOK {
		a.t.Fatalf("got status %d and %s from the login page, want 200", status, body)
	}
	return h
}

// framedClient returns a public Client that origins may frame the login page for.
func framedClient(id string, origins ...string) store.Client {
	c := publicClient(id, redirectURI)
	c.FrameAncestors = origins
	return c
}

// TestClientChoosesFramingOrigins checks that the origins registered for a Client, and only those, may frame the Host Application's login page for it.
//
//conformance:covers OAUTH21D16-7.11-04
func TestClientChoosesFramingOrigins(t *testing.T) {
	origins := []string{"https://portal.example", "https://shop.example:8443"}
	a := newFramingServer(t, framedClient("framed", origins...))
	if sources, _ := frameAncestors(a.loginPageHeaders("framed")); !slices.Equal(sources, origins) {
		t.Fatalf("got frame-ancestors %q, want %q", sources, origins)
	}
}

// TestFramedClientsAuthorizationCannotBeFramed checks that no origin can frame a response of the authorization endpoint for a Client with framing origins, which apply only to the Host Application's pages.
//
//conformance:covers RFC9700-4.16-01
func TestFramedClientsAuthorizationCannotBeFramed(t *testing.T) {
	a := newAuthorizationServer(t, framedClient("framed", "https://portal.example"))
	for _, h := range a.authorizationResponseHeaders("framed") {
		wantNoFrameAncestors(t, h)
	}
}

// TestInvalidFramingOriginsAreRefused checks that no origin may frame the Host Application's login page for a Client whose registered framing origins are not valid https origins.
func TestInvalidFramingOriginsAreRefused(t *testing.T) {
	a := newFramingServer(t, framedClient("framed", "https://portal.example; script-src *", "https://portal.example, https://evil.example", "http://portal.example", "*", "https://*.example", "https://portal.example/login", "'self'", "https://-portal.example", "https://portal.example:0", "https://portal.example:65536"))
	wantNoFraming(t, a.loginPageHeaders("framed"))
}

// newRenderingServer starts an Authorization Server whose RenderError writes an HTML error page.
func newRenderingServer(t *testing.T) *authorizationServer {
	t.Helper()
	return newConfiguredServer(t, func(c *oauth21.Config) {
		c.RenderError = func(w http.ResponseWriter, _ *http.Request, e oauth21.AuthorizationError) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(e.Status)
			_, _ = w.Write([]byte("<p>The request was refused.</p>"))
		}
	})
}

// renderedErrorHeaders returns the headers of the error page that RenderError writes for an unknown Client.
func (a *authorizationServer) renderedErrorHeaders() http.Header {
	a.t.Helper()
	status, h, body := a.send(http.MethodGet, "/authorize?"+unknownClientParams().Encode(), "", nil)
	if status != http.StatusBadRequest || string(body) != "<p>The request was refused.</p>" {
		a.t.Fatalf("got status %d and %s, want the rendered error page", status, body)
	}
	return h
}

// TestAuthorizationEndpointUsesCSP checks that every response of the authorization endpoint, an error page written by RenderError included, carries a Content-Security-Policy whose frame-ancestors allows no origin.
//
//conformance:covers OAUTH21D16-7.11-02
func TestAuthorizationEndpointUsesCSP(t *testing.T) {
	a := newRenderingServer(t)
	for _, h := range append(a.authorizationResponseHeaders(clientID), a.renderedErrorHeaders()) {
		wantNoFrameAncestors(t, h)
	}
}

// TestLoginPageUsesCSP checks that the Host Application's login page for a Client without framing origins carries a Content-Security-Policy whose frame-ancestors allows no origin.
//
//conformance:covers RFC9700-4.16-02
func TestLoginPageUsesCSP(t *testing.T) {
	wantNoFrameAncestors(t, newFramingServer(t).loginPageHeaders(clientID))
}

// TestFramingOriginsArePerClient checks that the login page of each Client may be framed only by the origins registered for that Client.
//
//conformance:covers RFC9700-4.16-04
func TestFramingOriginsArePerClient(t *testing.T) {
	a := newFramingServer(t, framedClient("portal", "https://portal.example"), framedClient("shop", "https://shop.example"))
	for id, want := range map[string][]string{"portal": {"https://portal.example"}, "shop": {"https://shop.example"}, clientID: {"'none'"}} {
		if sources, _ := frameAncestors(a.loginPageHeaders(id)); !slices.Equal(sources, want) {
			t.Fatalf("got frame-ancestors %q for %s, want %q", sources, id, want)
		}
	}
}

// TestAuthorizationEndpointSetsFrameOptions checks that every response of the authorization endpoint carries X-Frame-Options DENY with its Content-Security-Policy.
//
//conformance:covers OAUTH21D16-7.11-05
func TestAuthorizationEndpointSetsFrameOptions(t *testing.T) {
	for _, h := range newAuthorizationServer(t).authorizationResponseHeaders(clientID) {
		if _, ok := frameAncestors(h); !ok {
			t.Fatalf("got Content-Security-Policy %q, want frame-ancestors", h.Values("Content-Security-Policy"))
		}
		wantDenyFrameOptions(t, h)
	}
}

// TestFramedLoginPageSetsFrameOptions checks that the login page of a Client with framing origins still carries X-Frame-Options DENY.
//
//conformance:covers RFC9700-4.16-05
func TestFramedLoginPageSetsFrameOptions(t *testing.T) {
	a := newFramingServer(t, framedClient("framed", "https://portal.example"))
	wantDenyFrameOptions(t, a.loginPageHeaders("framed"))
}

// TestRenderedErrorPageSetsFrameOptions checks that an error page written by RenderError carries X-Frame-Options DENY besides its Content-Security-Policy.
//
//conformance:covers OAUTH21D16-7.11-06
func TestRenderedErrorPageSetsFrameOptions(t *testing.T) {
	wantDenyFrameOptions(t, newRenderingServer(t).renderedErrorHeaders())
}

// TestLoginPageSetsFrameOptions checks that the Host Application's login page for a Client without framing origins carries X-Frame-Options DENY besides its Content-Security-Policy.
//
//conformance:covers RFC9700-4.16-06
func TestLoginPageSetsFrameOptions(t *testing.T) {
	wantDenyFrameOptions(t, newFramingServer(t).loginPageHeaders(clientID))
}
