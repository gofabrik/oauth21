package wire

import (
	"context"
	"encoding/base64"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func get(query string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize", nil)
	r.URL.RawQuery = query
	return r
}

// encode returns the form encoding of the parsed fields.
func encode(fields map[string]*string) string {
	v := url.Values{}
	for name, field := range fields {
		v.Set(name, *field)
	}
	return v.Encode()
}

// basic returns an Authorization header carrying id and secret as client_secret_basic.
func basic(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
}

func post(body string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestParseAuthorizationParams(t *testing.T) {
	query := "response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fc.example%2Fcb&state=s&scope=a+b&code_challenge=x&code_challenge_method=S256"
	want := AuthorizationParams{"code", "c", "https://c.example/cb", "s", "a b", "x", "S256"}
	for name, r := range map[string]*http.Request{"GET": get(query), "POST": post(query)} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseAuthorizationParams(r)
			if err != nil || got != want {
				t.Fatalf("got %+v and error %v, want %+v", got, err, want)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	put := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/", nil)
	tests := map[string]func() *Error{
		"repeated authorization parameter": func() *Error { _, err := ParseAuthorizationParams(get("client_id=a&client_id=b")); return err },
		"malformed query":                  func() *Error { _, err := ParseAuthorizationParams(get("client_id=%zz")); return err },
		"authorization method":             func() *Error { _, err := ParseAuthorizationParams(put); return err },
		"repeated token parameter":         func() *Error { _, _, err := ParseTokenRequest(post("code=a&code=b")); return err },
		"malformed form":                   func() *Error { _, _, err := ParseTokenRequest(post("code=%zz")); return err },
		"token method":                     func() *Error { _, _, err := ParseTokenRequest(get("code=a")); return err },
		"repeated revocation parameter":    func() *Error { _, _, err := ParseRevocationRequest(post("token=a&token=b")); return err },
		"repeated token_type_hint": func() *Error {
			_, _, err := ParseRevocationRequest(post("token=a&token_type_hint=a&token_type_hint=b"))
			return err
		},
		"malformed revocation form": func() *Error { _, _, err := ParseRevocationRequest(post("token=%zz")); return err },
		"revocation method":         func() *Error { _, _, err := ParseRevocationRequest(get("token=a")); return err },
		"repeated revocation Authorization": func() *Error {
			r := post("token=a")
			r.Header["Authorization"] = []string{"Basic eDp5", "Bearer abc"}
			_, _, err := ParseRevocationRequest(r)
			return err
		},
	}
	for name, parse := range tests {
		t.Run(name, func(t *testing.T) {
			if err := parse(); err == nil || err.Code != "invalid_request" {
				t.Fatalf("got error %v, want invalid_request", err)
			}
		})
	}
}

func TestParseNamesFirstRepeatedParameter(t *testing.T) {
	for range 20 {
		_, err := ParseAuthorizationParams(get("state=a&state=b&client_id=a&client_id=b"))
		if err == nil || err.Description != "repeated parameter client_id" {
			t.Fatalf("got error %v, want client_id named", err)
		}
	}
}

func TestParseTreatsEmptyAsOmitted(t *testing.T) {
	for query, want := range map[string]string{"client_id=a&client_id=": "a", "client_id=&client_id=": ""} {
		got, err := ParseAuthorizationParams(get(query))
		if err != nil || got.ClientID != want {
			t.Errorf("%s: got client_id %q and error %v, want %q", query, got.ClientID, err, want)
		}
	}
}

func TestParseTokenRequestCredentials(t *testing.T) {
	r := post("client_id=c&client_secret=s")
	r.Header.Set("Authorization", "Basic YSUyMGIrYzpwJTNBJTI1Kw==")
	_, got, err := ParseTokenRequest(r)
	want := Credentials{ClientID: "c", ClientSecret: "s", AuthScheme: "Basic", BasicID: "a b c", BasicSecret: "p:% "}
	if err != nil || got != want {
		t.Fatalf("got %+v and error %v, want %+v", got, err, want)
	}
}

func TestParseTokenRequestAuthorization(t *testing.T) {
	for header, want := range map[string]Credentials{
		"basic eDp5":     {AuthScheme: "Basic", BasicID: "x", BasicSecret: "y"},
		"Basic Og==":     {AuthScheme: "Basic"},
		"Basic eDp5Onp6": {AuthScheme: "Basic", BasicID: "x", BasicSecret: "y:zz"},
		"Bearer abc":     {AuthScheme: "Bearer"},
		"Bearer":         {AuthScheme: "Bearer"},
		"Foo: x":         {AuthScheme: "Foo:"},
	} {
		r := post("")
		r.Header.Set("Authorization", header)
		if _, got, err := ParseTokenRequest(r); err != nil || got != want {
			t.Errorf("%q: got %+v and error %v, want %+v", header, got, err, want)
		}
	}
}

func TestParseTokenRequestRejectsRepeatedAuthorization(t *testing.T) {
	r := post("")
	r.Header["Authorization"] = []string{"Basic eDp5", "Bearer abc"}
	if _, _, err := ParseTokenRequest(r); err == nil || err.Code != "invalid_request" {
		t.Fatalf("got error %v, want invalid_request", err)
	}
}

func TestParseTokenRequestRejectsMalformedBasic(t *testing.T) {
	for _, header := range []string{"Basic", "Basic !!", "Basic eHk=", "Basic JXp6Onk=", "Basic eDolenk="} {
		r := post("")
		r.Header.Set("Authorization", header)
		if _, _, err := ParseTokenRequest(r); err == nil || err.Code != "invalid_client" {
			t.Errorf("%q: got error %v, want invalid_client", header, err)
		}
	}
}

func TestParseRevocationRequest(t *testing.T) {
	r := post("token=t&token_type_hint=refresh_token&client_id=c&client_secret=s")
	r.Header.Set("Authorization", "Basic YSUyMGIrYzpwJTNBJTI1Kw==")
	token, got, err := ParseRevocationRequest(r)
	want := Credentials{ClientID: "c", ClientSecret: "s", AuthScheme: "Basic", BasicID: "a b c", BasicSecret: "p:% "}
	if err != nil || token != "t" || got != want {
		t.Fatalf("got token %q, %+v and error %v, want t and %+v", token, got, err, want)
	}
}

func TestParseRevocationRequestRejectsMalformedBasic(t *testing.T) {
	r := post("token=t")
	r.Header.Set("Authorization", "Basic eHk=")
	if _, _, err := ParseRevocationRequest(r); err == nil || err.Code != "invalid_client" {
		t.Fatalf("got error %v, want invalid_client", err)
	}
}

func TestErrorStatus(t *testing.T) {
	for code, want := range map[string]int{
		"invalid_request":        http.StatusBadRequest,
		"invalid_grant":          http.StatusBadRequest,
		"unsupported_grant_type": http.StatusBadRequest,
		"invalid_client":         http.StatusBadRequest,
		"server_error":           http.StatusInternalServerError,
	} {
		if got := (&Error{Code: code}).Status(); got != want {
			t.Errorf("%s: got status %d, want %d", code, got, want)
		}
	}
}

func TestWriteErrorChallengesUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()
	WriteError(w, &Error{Code: "invalid_client"}, "Bearer")
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("got status %d and WWW-Authenticate %q, want 401 and Bearer", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	w = httptest.NewRecorder()
	WriteError(w, &Error{Code: "invalid_client"}, "Basic")
	if got := w.Header().Get("WWW-Authenticate"); got != `Basic realm="oauth21"` {
		t.Fatalf("got WWW-Authenticate %q, want a Basic challenge with a realm", got)
	}
	w = httptest.NewRecorder()
	WriteError(w, &Error{Code: "invalid_client"}, "")
	if w.Code != http.StatusBadRequest || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("got status %d and WWW-Authenticate %q, want 400 without a challenge", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}

func TestChallenge(t *testing.T) {
	for header, want := range map[string]string{"": "", "Bearer abc": "Bearer", "Basic eDp5": "Basic", "Foo: x": "Basic", "a\tb": "Basic"} {
		r := post("")
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		if got := Challenge(r); got != want {
			t.Errorf("%q: got challenge %q, want %q", header, got, want)
		}
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	WriteError(w, &Error{"invalid_grant", "bad code"}, "Basic")
	if w.Code != http.StatusBadRequest || w.Header().Get("Cache-Control") != "no-store" ||
		w.Body.String() != `{"error":"invalid_grant","error_description":"bad code"}`+"\n" {
		t.Fatalf("got status %d, headers %v and body %q", w.Code, w.Header(), w.Body.String())
	}
}

func TestAuthorizationResponse(t *testing.T) {
	a := AuthorizationResponse{RedirectURI: "https://c.example/cb", Issuer: "https://as.example"}
	got, err := a.Code("c")
	if want := "https://c.example/cb?code=c&iss=https%3A%2F%2Fas.example"; err != nil || got != want {
		t.Fatalf("got %q and error %v, want %q", got, err, want)
	}
	a.State = "s"
	got, err = a.Error(&Error{Code: "invalid_request"})
	if want := "https://c.example/cb?error=invalid_request&iss=https%3A%2F%2Fas.example&state=s"; err != nil || got != want {
		t.Fatalf("got %q and error %v, want %q", got, err, want)
	}
}

func TestRedirect(t *testing.T) {
	got, err := Redirect("https://c.example/cb?z=1&a=%41", url.Values{"code": {"a b"}, "state": {""}})
	if want := "https://c.example/cb?z=1&a=%41&code=a+b"; err != nil || got != want {
		t.Fatalf("got %q and error %v, want %q", got, err, want)
	}
}

func FuzzParseAuthorizationParams(f *testing.F) {
	f.Add("response_type=code&client_id=c&code_challenge=x&code_challenge_method=S256")
	f.Add("client_id=a&client_id=b")
	f.Add("state=%zz")
	f.Fuzz(func(t *testing.T, query string) {
		req, err := ParseAuthorizationParams(get(query))
		if err != nil {
			return
		}
		again, err := ParseAuthorizationParams(get(encode(req.fields())))
		if err != nil || again != req {
			t.Fatalf("got %+v and error %v after a round trip, want %+v", again, err, req)
		}
	})
}

func FuzzParseTokenRequest(f *testing.F) {
	f.Add("grant_type=authorization_code&code=c&client_id=c&code_verifier=v")
	f.Add("grant_type=refresh_token&refresh_token=r&scope=a+b&client_id=c")
	f.Add("code=a&code=b")
	f.Add("%zz")
	f.Fuzz(func(t *testing.T, body string) {
		req, c, err := ParseTokenRequest(post(body))
		if err != nil {
			return
		}
		fields := req.fields()
		maps.Copy(fields, c.fields())
		again, againCredentials, err := ParseTokenRequest(post(encode(fields)))
		if err != nil || again != req || againCredentials != c {
			t.Fatalf("got %+v, %+v and error %v after a round trip, want %+v and %+v", again, againCredentials, err, req, c)
		}
	})
}

func FuzzParseTokenRequestBasic(f *testing.F) {
	f.Add("client", "secret")
	f.Add("a b+c", "p:%")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, id, secret string) {
		r := post("")
		r.Header.Set("Authorization", basic(id, secret))
		_, got, err := ParseTokenRequest(r)
		if want := (Credentials{AuthScheme: "Basic", BasicID: id, BasicSecret: secret}); err != nil || got != want {
			t.Fatalf("got %+v and error %v, want %+v", got, err, want)
		}
	})
}

func FuzzParseTokenRequestAuthorization(f *testing.F) {
	f.Add("Basic eDp5")
	f.Add("Basic JXp6Onk=")
	f.Add("Bearer abc")
	f.Add("")
	f.Fuzz(func(t *testing.T, header string) {
		r := post("")
		r.Header["Authorization"] = []string{header}
		_, got, err := ParseTokenRequest(r)
		if err != nil {
			if err.Code != "invalid_client" {
				t.Fatalf("got error %v, want invalid_client", err)
			}
			return
		}
		if got.AuthScheme != "Basic" && (got.BasicID != "" || got.BasicSecret != "") {
			t.Fatalf("got %+v, want Basic credentials only with the Basic scheme", got)
		}
	})
}

func FuzzParseRevocationRequest(f *testing.F) {
	f.Add("token=t&token_type_hint=access_token&client_id=c", "")
	f.Add("token=t", "Basic eDp5")
	f.Add("token=a&token=b", "")
	f.Add("%zz", "Bearer abc")
	f.Fuzz(func(t *testing.T, body, header string) {
		r := post(body)
		r.Header["Authorization"] = []string{header}
		token, c, err := ParseRevocationRequest(r)
		if err != nil {
			if err.Code != "invalid_request" && err.Code != "invalid_client" {
				t.Fatalf("got error %v, want invalid_request or invalid_client", err)
			}
			return
		}
		fields := c.fields()
		fields["token"] = &token
		r = post(encode(fields))
		switch c.AuthScheme {
		case "":
		case "Basic":
			r.Header.Set("Authorization", basic(c.BasicID, c.BasicSecret))
		default:
			r.Header.Set("Authorization", c.AuthScheme)
		}
		again, againCredentials, err := ParseRevocationRequest(r)
		if err != nil || again != token || againCredentials != c {
			t.Fatalf("got token %q, %+v and error %v after a round trip, want %q and %+v", again, againCredentials, err, token, c)
		}
	})
}
