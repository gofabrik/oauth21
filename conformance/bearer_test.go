package conformance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofabrik/oauth21/bearer"
	"github.com/gofabrik/oauth21/store"
)

// validators builds each Validator the bearer middleware is tested with.
var validators = map[string]func(a *authorizationServer) bearer.Validator{
	"local":  func(a *authorizationServer) bearer.Validator { return a.local() },
	"remote": func(a *authorizationServer) bearer.Validator { return a.remote(resourceServerID, secret) },
}

// local returns the local validator of the Resource Server Client.
func (a *authorizationServer) local() bearer.Local {
	return bearer.Local{Tokens: a.recorder, ClientID: resourceServerID, Clock: a.now}
}

// remote returns the remote validator authenticating as id with clientSecret.
func (a *authorizationServer) remote(id, clientSecret string) bearer.Remote {
	return bearer.Remote{Endpoint: a.url + a.srv.Paths().Introspection, ClientID: id, ClientSecret: clientSecret, Client: a.client}
}

// forEachValidator runs test with each validator, against a new Authorization Server where the Resource Server Client may introspect.
func forEachValidator(t *testing.T, test func(a *authorizationServer, v bearer.Validator)) {
	t.Helper()
	for name, validator := range validators {
		t.Run(name, func(t *testing.T) {
			a := newIntrospectionServer(t)
			test(a, validator(a))
		})
	}
}

// resource serves the validated token of a request guarded by the bearer middleware with v that requires scopes.
func (a *authorizationServer) resource(v bearer.Validator, scopes ...string) {
	a.t.Helper()
	a.mux.Handle("/resource", bearer.Middleware(v, scopes...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := bearer.FromContext(r.Context())
		_ = json.NewEncoder(w).Encode(token)
	})))
}

// access sends a request with header to the protected resource and returns the status, headers and body of the response.
func (a *authorizationServer) access(header http.Header) (int, http.Header, []byte) {
	a.t.Helper()
	return a.send(http.MethodGet, "/resource", "", header)
}

// bearerHeader returns an Authorization header carrying token.
func bearerHeader(token string) http.Header {
	return http.Header{"Authorization": {"Bearer " + token}}
}

// wantChallenge checks that a request with header to the protected resource gets wantStatus and the Bearer challenge want.
func (a *authorizationServer) wantChallenge(header http.Header, wantStatus int, want string) {
	a.t.Helper()
	status, respHeader, _ := a.access(header)
	if status != wantStatus || respHeader.Get("WWW-Authenticate") != want {
		a.t.Fatalf("got status %d and WWW-Authenticate %q, want %d and %q", status, respHeader.Get("WWW-Authenticate"), wantStatus, want)
	}
}

// TestBearerTokenReachesHandler checks that a valid access token in the Authorization header gives the handler its subject, Client and scopes.
//
//conformance:covers OAUTH21D16-5.1.1-02
func TestBearerTokenReachesHandler(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v, "read")
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		status, _, body := a.access(bearerHeader(access))
		var got bearer.Token
		if err := json.Unmarshal(body, &got); err != nil || status != http.StatusOK || got.Subject != "alice" || got.ClientID != clientID || len(got.Scopes) != 1 || got.Scopes[0] != "read" {
			a.t.Fatalf("got status %d, body %s and error %v, want the token of alice and %s with scope read", status, body, err, clientID)
		}
	})
}

// TestBearerChallengeWithoutCredentials checks that a request without Bearer credentials in the Authorization header gets 401 and a challenge without error, also when it carries an access token in the query or the body.
//
//conformance:covers OAUTH21D16-5.3.2-06
func TestBearerChallengeWithoutCredentials(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		want := `Bearer realm="oauth21"`
		a.wantChallenge(nil, http.StatusUnauthorized, want)
		a.wantChallenge(basic(clientID, access), http.StatusUnauthorized, want)
		for _, r := range []struct{ method, path, form string }{
			{http.MethodGet, "/resource?access_token=" + access, ""},
			{http.MethodPost, "/resource", "access_token=" + access},
		} {
			status, header, _ := a.send(r.method, r.path, r.form, nil)
			if status != http.StatusUnauthorized || header.Get("WWW-Authenticate") != want {
				a.t.Fatalf("%s %s: got status %d and WWW-Authenticate %q, want 401 and %q", r.method, r.path, status, header.Get("WWW-Authenticate"), want)
			}
		}
	})
}

// TestBearerChallengeForInvalidToken checks that unknown, expired and revoked access tokens and refresh tokens get 401 and an invalid_token challenge.
//
//conformance:covers OAUTH21D16-5.3.2-02
func TestBearerChallengeForInvalidToken(t *testing.T) {
	want := `Bearer realm="oauth21", error="invalid_token", error_description="access token not active"`
	t.Run("unknown", func(t *testing.T) {
		forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
			a.resource(v)
			a.wantChallenge(bearerHeader("unknown"), http.StatusUnauthorized, want)
		})
	})
	t.Run("expired", func(t *testing.T) {
		forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
			a.resource(v)
			access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
			a.advance(time.Hour)
			a.wantChallenge(bearerHeader(access), http.StatusUnauthorized, want)
		})
	})
	t.Run("revoked access token", func(t *testing.T) {
		forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
			a.resource(v)
			access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
			a.revoke(revocationParams(access), nil)
			a.wantChallenge(bearerHeader(access), http.StatusUnauthorized, want)
		})
	})
	t.Run("access token of a revoked Grant", func(t *testing.T) {
		forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
			a.resource(v)
			access, refresh := a.tokens(tokenParams(a.code(authorizeParams())), nil)
			a.revoke(revocationParams(refresh), nil)
			a.wantChallenge(bearerHeader(access), http.StatusUnauthorized, want)
		})
	})
	t.Run("refresh token", func(t *testing.T) {
		forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
			a.resource(v)
			a.wantChallenge(bearerHeader(a.publicRefreshToken()), http.StatusUnauthorized, want)
		})
	})
}

// TestBearerChallengeForMalformedRequest checks that malformed Bearer credentials and a repeated Authorization header get 400 and an invalid_request challenge.
//
//conformance:covers OAUTH21D16-5.3.2-01
func TestBearerChallengeForMalformedRequest(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		want := `Bearer realm="oauth21", error="invalid_request", error_description="malformed Bearer credentials"`
		for _, credentials := range []string{"Bearer", "Bearer a b", "Bearer =abc"} {
			a.wantChallenge(http.Header{"Authorization": {credentials}}, http.StatusBadRequest, want)
		}
		repeated := http.Header{"Authorization": {"Bearer " + access, "Bearer " + access}}
		a.wantChallenge(repeated, http.StatusBadRequest, `Bearer realm="oauth21", error="invalid_request", error_description="repeated Authorization header"`)
	})
}

// TestBearerChallengeForInsufficientScope checks that an access token without a required scope gets 403 and an insufficient_scope challenge with the required scopes, and that the scheme is case-insensitive.
//
//conformance:covers OAUTH21D16-5.3.2-04
func TestBearerChallengeForInsufficientScope(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v, "read", "write")
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.wantChallenge(http.Header{"Authorization": {"bEaReR " + access}}, http.StatusForbidden, `Bearer realm="oauth21", scope="read write", error="insufficient_scope", error_description="access token lacks a required scope"`)
		a.wantChallenge(nil, http.StatusUnauthorized, `Bearer realm="oauth21", scope="read write"`)
		params := authorizeParams()
		params.Set("scope", "read write")
		access, _ = a.tokens(tokenParams(a.code(params)), nil)
		if status, _, body := a.access(http.Header{"Authorization": {"bEaReR " + access}}); status != http.StatusOK {
			a.t.Fatalf("got status %d and body %s with both scopes, want 200", status, body)
		}
	})
}

// TestBearerRemoteValidationFailureIsServerError checks that the remote validator gets 500 without a challenge when introspection fails: its credentials are invalid, its Client may not introspect, or the endpoint is missing, unreachable or redirects, even with an HTTP client that follows redirects.
func TestBearerRemoteValidationFailureIsServerError(t *testing.T) {
	for name, v := range map[string]func(a *authorizationServer) bearer.Remote{
		"invalid credentials":       func(a *authorizationServer) bearer.Remote { return a.remote(resourceServerID, "wrong") },
		"Client without Introspect": func(a *authorizationServer) bearer.Remote { return a.remote(confidentialID, secret) },
		"missing endpoint": func(a *authorizationServer) bearer.Remote {
			r := a.remote(resourceServerID, secret)
			r.Endpoint = a.url + "/missing"
			return r
		},
		"unreachable endpoint": func(a *authorizationServer) bearer.Remote {
			closed := httptest.NewServer(http.NotFoundHandler())
			closed.Close()
			r := a.remote(resourceServerID, secret)
			r.Endpoint = closed.URL + a.srv.Paths().Introspection
			return r
		},
		"redirecting endpoint": func(a *authorizationServer) bearer.Remote {
			a.mux.Handle("/moved", http.RedirectHandler(a.srv.Paths().Introspection, http.StatusTemporaryRedirect))
			client := *a.client
			client.CheckRedirect = nil
			r := a.remote(resourceServerID, secret)
			r.Endpoint, r.Client = a.url+"/moved", &client
			return r
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := newIntrospectionServer(t)
			a.resource(v(a))
			access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
			if status, header, _ := a.access(bearerHeader(access)); status != http.StatusInternalServerError || header.Get("WWW-Authenticate") != "" {
				t.Fatalf("got status %d and WWW-Authenticate %q, want 500 without a challenge", status, header.Get("WWW-Authenticate"))
			}
		})
	}
}

// challenges returns the WWW-Authenticate challenges of a resource that requires read and write: for a request without credentials, and, as failures, for an unknown access token, an access token lacking write, malformed credentials and a repeated Authorization header.
func (a *authorizationServer) challenges(v bearer.Validator) (withoutCredentials string, failures []string) {
	a.t.Helper()
	a.resource(v, "read", "write")
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	_, header, _ := a.access(nil)
	withoutCredentials = header.Get("WWW-Authenticate")
	for _, h := range []http.Header{bearerHeader("unknown"), bearerHeader(access), {"Authorization": {"Bearer a b"}}, {"Authorization": {"Bearer " + access, "Bearer " + access}}} {
		_, header, _ := a.access(h)
		failures = append(failures, header.Get("WWW-Authenticate"))
	}
	return withoutCredentials, failures
}

// allChallenges returns every challenge of challenges and the challenge of a resource without required scopes for a request without credentials.
func (a *authorizationServer) allChallenges(v bearer.Validator) []string {
	a.t.Helper()
	withoutCredentials, failures := a.challenges(v)
	a.mux.Handle("/unscoped", bearer.Middleware(v)(http.NotFoundHandler()))
	_, header, _ := a.send(http.MethodGet, "/unscoped", "", nil)
	return append([]string{withoutCredentials, header.Get("WWW-Authenticate")}, failures...)
}

// authParam is an auth-param of a challenge, with the value as sent: a quoted-string keeps its quotes and escapes.
type authParam struct{ name, value string }

// parseChallenge parses the challenge c into its auth-scheme and auth-params (RFC 9110 11.6.1), and reports whether c is well-formed.
func parseChallenge(c string) (string, []authParam, bool) {
	scheme, rest, _ := strings.Cut(c, " ")
	if scheme == "" || strings.ContainsFunc(scheme, func(r rune) bool { return !tokenChar(r) }) {
		return "", nil, false
	}
	var params []authParam
	for {
		rest = strings.TrimLeft(rest, " \t,")
		if rest == "" {
			return scheme, params, true
		}
		n := strings.IndexFunc(rest, func(r rune) bool { return !tokenChar(r) })
		if n <= 0 {
			return "", nil, false
		}
		name := rest[:n]
		rest = strings.TrimLeft(rest[n:], " \t")
		if !strings.HasPrefix(rest, "=") {
			return "", nil, false
		}
		rest = strings.TrimLeft(rest[1:], " \t")
		var value string
		if strings.HasPrefix(rest, `"`) {
			end := 1
			for end < len(rest) && rest[end] != '"' {
				if rest[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(rest) {
				return "", nil, false
			}
			value, rest = rest[:end+1], rest[end+1:]
		} else {
			n := strings.IndexFunc(rest, func(r rune) bool { return !tokenChar(r) })
			if n < 0 {
				n = len(rest)
			}
			if n == 0 {
				return "", nil, false
			}
			value, rest = rest[:n], rest[n:]
		}
		params = append(params, authParam{strings.ToLower(name), value})
		if rest = strings.TrimLeft(rest, " \t"); rest != "" && rest[0] != ',' {
			return "", nil, false
		}
	}
}

// tokenChar reports whether c may appear in an HTTP token (RFC 9110 5.6.2).
func tokenChar(c rune) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)
}

// wantParsed parses the challenge c and fails the test when it is malformed.
func (a *authorizationServer) wantParsed(c string) (string, []authParam) {
	a.t.Helper()
	scheme, params, ok := parseChallenge(c)
	if !ok {
		a.t.Fatalf("got malformed challenge %q", c)
	}
	return scheme, params
}

// quoted returns the content of the quoted-string value of the auth-param name in params, and whether params has it.
func quoted(params []authParam, name string) (string, bool) {
	for _, p := range params {
		if p.name == name {
			return strings.TrimSuffix(strings.TrimPrefix(p.value, `"`), `"`), true
		}
	}
	return "", false
}

// TestBearerIgnoresQueryToken checks that an access token in the query does not authenticate a request.
//
//conformance:covers OAUTH21D16-5.1-04
func TestBearerIgnoresQueryToken(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		if status, _, _ := a.send(http.MethodGet, "/resource?access_token="+access, "", nil); status != http.StatusUnauthorized {
			a.t.Fatalf("got status %d, want 401", status)
		}
	})
}

// TestBearerChallengesMissingCredentials checks that a request without credentials, with an unknown access token or with an access token lacking a required scope gets a WWW-Authenticate header.
//
//conformance:covers OAUTH21D16-5.3.1-01
func TestBearerChallengesMissingCredentials(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v, "write")
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		for _, h := range []http.Header{nil, bearerHeader("unknown"), bearerHeader(access)} {
			if _, header, _ := a.access(h); header.Get("WWW-Authenticate") == "" {
				a.t.Fatalf("got no WWW-Authenticate header with %v", h)
			}
		}
	})
}

// TestBearerChallengeScheme checks that every challenge uses the Bearer scheme.
//
//conformance:covers OAUTH21D16-5.3.1-03
func TestBearerChallengeScheme(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		for _, c := range a.allChallenges(v) {
			if scheme, _ := a.wantParsed(c); scheme != "Bearer" {
				a.t.Fatalf("got challenge %q, want the Bearer scheme", c)
			}
		}
	})
}

// TestBearerChallengeHasAuthParams checks that every challenge has at least one auth-param after the scheme.
//
//conformance:covers OAUTH21D16-5.3.1-04
func TestBearerChallengeHasAuthParams(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		for _, c := range a.allChallenges(v) {
			if _, params := a.wantParsed(c); len(params) == 0 {
				a.t.Fatalf("got challenge %q, want auth-params", c)
			}
		}
	})
}

// wantAttributeAtMostOnce checks that no challenge of v has one of the attributes names more than once.
func (a *authorizationServer) wantAttributeAtMostOnce(v bearer.Validator, names ...string) {
	a.t.Helper()
	for _, c := range a.allChallenges(v) {
		_, params := a.wantParsed(c)
		seen := map[string]bool{}
		for _, p := range params {
			if slices.Contains(names, p.name) && seen[p.name] {
				a.t.Fatalf("got challenge %q, want %s at most once", c, p.name)
			}
			seen[p.name] = true
		}
	}
}

// TestBearerChallengeRealmOnce checks that no challenge has realm more than once.
//
//conformance:covers OAUTH21D16-5.3.1-07
func TestBearerChallengeRealmOnce(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.wantAttributeAtMostOnce(v, "realm")
	})
}

// TestBearerChallengeScopeOnce checks that no challenge has scope more than once.
//
//conformance:covers OAUTH21D16-5.3.1-09
func TestBearerChallengeScopeOnce(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.wantAttributeAtMostOnce(v, "scope")
	})
}

// TestBearerChallengeErrorAttributesOnce checks that no challenge has error, error_description or error_uri more than once.
//
//conformance:covers OAUTH21D16-5.3.1-13
func TestBearerChallengeErrorAttributesOnce(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.wantAttributeAtMostOnce(v, "error", "error_description", "error_uri")
	})
}

// scopeChars reports whether s is scope-tokens of %x21 / %x23-5B / %x5D-7E delimited by single spaces.
func scopeChars(s string) bool {
	for token := range strings.SplitSeq(s, " ") {
		if token == "" || strings.ContainsFunc(token, func(r rune) bool { return r < 0x21 || r > 0x7e || r == '"' || r == '\\' }) {
			return false
		}
	}
	return true
}

// TestBearerChallengeScopeCharacters checks that the scope attribute of every challenge of a resource requiring scopes uses only the allowed characters.
//
//conformance:covers OAUTH21D16-5.3.1-14
func TestBearerChallengeScopeCharacters(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		withoutCredentials, failures := a.challenges(v)
		for _, c := range append(failures, withoutCredentials) {
			_, params := a.wantParsed(c)
			if scope, ok := quoted(params, "scope"); !ok || !scopeChars(scope) {
				a.t.Fatalf("got challenge %q, want a scope of the allowed characters", c)
			}
		}
	})
}

// TestBearerChallengeErrorCharacters checks that the error and error_description attributes of every error challenge use only the allowed characters.
//
//conformance:covers OAUTH21D16-5.3.1-15
func TestBearerChallengeErrorCharacters(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		_, failures := a.challenges(v)
		for _, c := range failures {
			_, params := a.wantParsed(c)
			for _, name := range []string{"error", "error_description"} {
				if value, ok := quoted(params, name); !ok || value == "" || !errorChars(value) {
					a.t.Fatalf("got challenge %q, want %s of the allowed characters", c, name)
				}
			}
		}
	})
}

// wantAccess checks that a request with the access token to the protected resource gets wantStatus.
func (a *authorizationServer) wantAccess(token string, wantStatus int) {
	a.t.Helper()
	if status, header, _ := a.access(bearerHeader(token)); status != wantStatus {
		a.t.Fatalf("got status %d and WWW-Authenticate %q, want %d", status, header.Get("WWW-Authenticate"), wantStatus)
	}
}

// TestBearerRefusesExpiredToken checks that an expired access token is refused with 401.
//
//conformance:covers OAUTH21D16-5.2-01
func TestBearerRefusesExpiredToken(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.advance(time.Hour)
		a.wantAccess(access, http.StatusUnauthorized)
	})
}

// audienceToken stores an access token of alice and the public Client with scope read and audience, which only the Store can give it, and returns its value.
func (a *authorizationServer) audienceToken(audience ...string) string {
	a.t.Helper()
	return a.storedToken(readScope, audience...)
}

// storedToken stores an access token of alice and the public Client with scopes and audience, which only the Store can give it, and returns its value.
func (a *authorizationServer) storedToken(scopes []string, audience ...string) string {
	a.t.Helper()
	value, hash := randomWithHash(a.t)
	if err := a.recorder.Store.CreateToken(a.t.Context(), store.Token{Hash: hash, Grant: aliceGrant("grant-"+value, audience...), Scopes: scopes, Audience: audience, ExpiresAt: a.now().Add(time.Hour)}); err != nil {
		a.t.Fatal(err)
	}
	return value
}

// otherAudiences are audiences that name only Resource Servers other than the Resource Server Client, some close to its Client identifier.
var otherAudiences = [][]string{{"other"}, {"other", "another"}, {strings.ToLower(resourceServerID)}, {resourceServerID + " 2"}, {"The " + resourceServerID}, {" " + resourceServerID}, {resourceServerID + " "}}

// otherScopes are scopes close to read and write that a resource requiring both refuses.
var otherScopes = [][]string{{"read", "writer"}, {"READ", "WRITE"}, {"read", "Write"}}

// TestBearerChecksAudience checks that an access token is served by a Resource Server its audience names, alone or with others, and refused when its audience names only another.
//
//conformance:covers OAUTH21D16-5.2-02
func TestBearerChecksAudience(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		a.wantAccess(a.audienceToken(resourceServerID), http.StatusOK)
		a.wantAccess(a.audienceToken("other", resourceServerID), http.StatusOK)
		a.wantAccess(a.audienceToken("other"), http.StatusUnauthorized)
	})
}

// TestBearerRefusesTokenForOtherResourceServer checks that an access token whose audience names only other Resource Servers is refused, also when one differs from the Resource Server only in case or by a prefix or suffix.
//
//conformance:covers OAUTH21D16-7.1.4-03
func TestBearerRefusesTokenForOtherResourceServer(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		for _, audience := range otherAudiences {
			a.wantAccess(a.audienceToken(audience...), http.StatusUnauthorized)
		}
	})
}

// TestRemoteValidationRefusesTokenForOtherResourceServer checks that introspection makes the remote validator refuse an access token meant for another Resource Server, also one whose identifier is close to its own.
//
//conformance:covers OAUTH21D16-7.3.2-06
func TestRemoteValidationRefusesTokenForOtherResourceServer(t *testing.T) {
	a := newIntrospectionServer(t)
	a.resource(a.remote(resourceServerID, secret))
	for _, audience := range otherAudiences {
		token := a.audienceToken(audience...)
		a.wantInactive(token)
		a.wantAccess(token, http.StatusUnauthorized)
	}
}

// TestBearerChecksScope checks that a resource requiring read and write serves an access token with both and refuses one with only read or with read and writer.
//
//conformance:covers OAUTH21D16-5.2-03
func TestBearerChecksScope(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v, "read", "write")
		params := authorizeParams()
		params.Set("scope", "read write")
		both, _ := a.tokens(tokenParams(a.code(params)), nil)
		read, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.wantAccess(both, http.StatusOK)
		a.wantAccess(read, http.StatusForbidden)
		for _, scopes := range otherScopes {
			a.wantAccess(a.storedToken(scopes), http.StatusForbidden)
		}
	})
}

// TestBearerHandlerGetsTokenDetails checks that the handler gets the subject, Client, scopes and audience of the validated access token to apply its own policy.
//
//conformance:covers OAUTH21D16-5.2-04
func TestBearerHandlerGetsTokenDetails(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		status, _, body := a.access(bearerHeader(a.audienceToken(resourceServerID)))
		var got bearer.Token
		if err := json.Unmarshal(body, &got); err != nil || status != http.StatusOK || got.Subject != "alice" || got.ClientID != clientID || !slices.Equal(got.Scopes, readScope) || !slices.Equal(got.Audience, []string{resourceServerID}) {
			a.t.Fatalf("got status %d, body %s and error %v, want the details of the token", status, body, err)
		}
	})
}

// TestBearerRefusesTokenWithoutScope checks that an access token without one of the scopes the resource requires is refused with 403, also when it has a scope that only contains the missing one.
//
//conformance:covers OAUTH21D16-7.1.4-06
func TestBearerRefusesTokenWithoutScope(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v, "read", "write")
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.wantAccess(access, http.StatusForbidden)
		for _, scopes := range otherScopes {
			a.wantAccess(a.storedToken(scopes), http.StatusForbidden)
		}
	})
}

// TestBearerValidatesToken checks that a resource serves an access token the server issued and refuses a value it never issued.
//
//conformance:covers OAUTH21D16-5-01
func TestBearerValidatesToken(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.wantAccess(access, http.StatusOK)
		a.wantAccess(random(a.t), http.StatusUnauthorized)
	})
}

// TestBearerRefusesTokenAtExpiry checks that an access token is served until the end of its lifetime and refused from then on.
//
//conformance:covers OAUTH21D16-5-02
func TestBearerRefusesTokenAtExpiry(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v)
		access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.advance(time.Hour - time.Second)
		a.wantAccess(access, http.StatusOK)
		a.advance(time.Second)
		a.wantAccess(access, http.StatusUnauthorized)
	})
}

// TestBearerServesCoveringScope checks that an access token with more scopes than a resource requires is served, and one whose scopes do not cover the resource is refused.
//
//conformance:covers OAUTH21D16-5-03
func TestBearerServesCoveringScope(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		a.resource(v, "write")
		params := authorizeParams()
		params.Set("scope", "read write")
		access, _ := a.tokens(tokenParams(a.code(params)), nil)
		a.wantAccess(access, http.StatusOK)
		read, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
		a.wantAccess(read, http.StatusForbidden)
	})
}

// TestRemoteValidationChecksCertificates checks that the remote validator refuses an introspection endpoint whose TLS certificate its HTTP client does not trust or that does not name the endpoint host.
//
//conformance:covers OAUTH21D16-1.5-04
func TestRemoteValidationChecksCertificates(t *testing.T) {
	for name, v := range map[string]func(a *authorizationServer) bearer.Remote{
		"untrusted certificate": func(a *authorizationServer) bearer.Remote {
			r := a.remote(resourceServerID, secret)
			r.Client = &http.Client{}
			return r
		},
		"certificate for another host": func(a *authorizationServer) bearer.Remote {
			r := a.remote(resourceServerID, secret)
			r.Endpoint = strings.Replace(r.Endpoint, "127.0.0.1", "localhost", 1)
			return r
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := newIntrospectionServer(t)
			a.resource(v(a))
			access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
			if status, _, _ := a.access(bearerHeader(access)); status != http.StatusInternalServerError {
				t.Fatalf("got status %d, want 500", status)
			}
		})
	}
}

// TestBearerChallengeErrorURIIsURIReference checks that a challenge carries error_uri only as a URI-reference.
//
//conformance:covers OAUTH21D16-5.3.1-16
func TestBearerChallengeErrorURIIsURIReference(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		for _, c := range a.allChallenges(v) {
			_, params := a.wantParsed(c)
			if uri, ok := quoted(params, "error_uri"); ok && !uriReference(uri) {
				a.t.Fatalf("got challenge %q, want error_uri as a URI-reference", c)
			}
		}
	})
}

// TestBearerChallengeErrorURICharacters checks that a challenge carries error_uri only with the allowed characters.
//
//conformance:covers OAUTH21D16-5.3.1-17
func TestBearerChallengeErrorURICharacters(t *testing.T) {
	forEachValidator(t, func(a *authorizationServer, v bearer.Validator) {
		for _, c := range a.allChallenges(v) {
			_, params := a.wantParsed(c)
			if uri, ok := quoted(params, "error_uri"); ok && !uriChars(uri) {
				a.t.Fatalf("got challenge %q, want error_uri of the allowed characters", c)
			}
		}
	})
}
