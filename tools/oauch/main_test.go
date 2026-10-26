package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

const (
	siteID    = "0b5c3c6e-6d1f-4a51-9f4e-2a8f0c1d7e93"
	managerID = "7d0e9a1b-3c2f-4e8d-8a6b-5f4c3b2a1d0e"
)

// exportJSON is an OAuch export with one test run of five tests.
const exportJSON = `[{"Name":"oauth21","TestRuns":[{"StartedAt":"2026-10-26T03:00:00.2655913","TestResults":[
{"$type":"OAuch.Compliance.Tests.Pkce.HashedPkceTestResult, OAuch.Compliance","TestId":"OAuch.Compliance.Tests.Pkce.HashedPkceTest","Outcome":0},
{"TestId":"OAuch.Compliance.Tests.Tokens.RefreshTokenRevokedTest","Outcome":1},
{"TestId":"OAuch.Compliance.Tests.Features.ImplicitFlowSupportedTest","Outcome":3},
{"TestId":"OAuch.Compliance.Tests.Tokens.TokenEntropyTest","Outcome":4},
{"TestId":"OAuch.Compliance.Tests.Tokens.RefreshTokenRotationTest","Outcome":null}]}]}]`

// authorizationServer is a fake of the example Authorization Server with login and consent pages.
type authorizationServer struct {
	*httptest.Server
	callback string
}

func newAuthorizationServer(t *testing.T) *authorizationServer {
	t.Helper()
	as := &authorizationServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 as.URL,
			"authorization_endpoint": as.URL + "/authorize",
			"token_endpoint":         as.URL + "/token",
			"revocation_endpoint":    as.URL + "/revoke",
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		as.callback = r.FormValue("redirect_uri") + "?code=c0de&state=" + url.QueryEscape(r.FormValue("state"))
		http.Redirect(w, r, "/login?request_id=r1", http.StatusFound)
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `<form method="post"><input type="hidden" name="request_id" value="%s">
<input name="username" value="demo"><input name="password" type="password"><button>Log in</button></form>`, r.FormValue("request_id"))
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("username") != "demo" || r.PostFormValue("password") != "demo" || r.PostFormValue("decision") != "" {
			http.Error(w, "wrong login", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "login", Value: "l1", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/consent?request_id="+r.PostFormValue("request_id"), http.StatusSeeOther)
	})
	mux.HandleFunc("GET /consent", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `<form method="post"><input type="hidden" name="request_id" value="%s">
<button name="decision" value="allow">Allow</button><button name="decision" value="deny">Deny</button></form>`, r.FormValue("request_id"))
	})
	mux.HandleFunc("POST /consent", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("login"); err != nil || c.Value != "l1" || r.PostFormValue("decision") != "allow" || r.PostFormValue("request_id") != "r1" {
			http.Error(w, "no consent", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, as.callback, http.StatusSeeOther)
	})
	mux.HandleFunc("GET /invalid", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
	})
	as.Server = httptest.NewTLSServer(mux)
	t.Cleanup(as.Close)
	return as
}

// oauch is a fake of OAuch whose test run authorizes at the Authorization Server with a GET and a POST request, and then stalls once on an error page.
type oauch struct {
	*httptest.Server
	t  *testing.T
	as *authorizationServer

	mu       sync.Mutex
	site     string
	invoked  []string
	outgoing chan string
	// callbacks counts the OnCallback invocations.
	callbacks int
	// fail is the error the test run reports when it starts, if any.
	fail string
	// authorize is the authorization endpoint the test run sends the pop-up to.
	authorize string
}

func newOAuch(t *testing.T, as *authorizationServer) *oauch {
	t.Helper()
	o := &oauch{t: t, as: as, outgoing: make(chan string, 16), authorize: as.URL + "/authorize"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "s1", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/Dashboard", http.StatusFound)
	})
	mux.HandleFunc("POST /Dashboard/Import", o.authenticated(func(w http.ResponseWriter, r *http.Request) {
		f, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b, _ := io.ReadAll(f)
		o.mu.Lock()
		o.site = string(b)
		o.mu.Unlock()
		http.Redirect(w, r, "/Dashboard", http.StatusFound)
	}))
	mux.HandleFunc("GET /Dashboard", o.authenticated(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `<a href="/Dashboard/Results/%s" class="nav-link">`, siteID)
	}))
	mux.HandleFunc("GET /Dashboard/Running/"+siteID, o.authenticated(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `<script>var testId = "%s";</script>`, managerID)
	}))
	mux.HandleFunc("GET /Callback/PostRedirect/"+managerID, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `<form action="%s/authorize" method="post" id="theForm">`, o.as.URL)
		for k, v := range o.authorization() {
			_, _ = fmt.Fprintf(w, `<input type="hidden" id="%[1]s" name="%[1]s" value="%[2]s">`, k, html.EscapeString(v[0]))
		}
		_, _ = io.WriteString(w, `</form><script>document.getElementById("theForm").submit();</script>`)
	})
	mux.HandleFunc("GET /Dashboard/ExportData/"+siteID, o.authenticated(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, exportJSON)
	}))
	mux.HandleFunc("POST /testrunhub/negotiate", o.authenticated(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"negotiateVersion":1,"connectionId":"c1","connectionToken":"t1","availableTransports":[{"transport":"LongPolling","transferFormats":["Text"]}]}`)
	}))
	mux.HandleFunc("POST /testrunhub", o.authenticated(o.receive))
	mux.HandleFunc("GET /testrunhub", o.authenticated(o.poll))
	o.Server = httptest.NewTLSServer(mux)
	t.Cleanup(o.Close)
	return o
}

// authorization is the authorization request of the fake OAuch at the Authorization Server.
func (o *oauch) authorization() url.Values {
	return url.Values{"redirect_uri": {o.URL + "/Callback"}, "state": {"s 1"}}
}

func (o *oauch) authenticated(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "s1" {
			http.Error(w, "no session", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// receive handles the frames the driver sends and answers them like the test run hub.
func (o *oauch) receive(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("id") != "t1" {
		http.Error(w, "unknown connection", http.StatusNotFound)
		return
	}
	b, _ := io.ReadAll(r.Body)
	for frame := range strings.SplitSeq(strings.TrimSuffix(string(b), "\x1e"), "\x1e") {
		var m struct {
			Target    string   `json:"target"`
			Arguments []string `json:"arguments"`
		}
		_ = json.Unmarshal([]byte(frame), &m)
		invoked := frame
		if m.Target != "" {
			invoked = fmt.Sprintf("%s%q", m.Target, m.Arguments)
		}
		o.mu.Lock()
		o.invoked = append(o.invoked, invoked)
		o.mu.Unlock()
		switch m.Target {
		case "":
			o.outgoing <- `{}`
		case "OnReady":
			if o.fail != "" {
				o.outgoing <- `{"type":1,"target":"OnError","arguments":["` + o.fail + `"]}`
				break
			}
			o.outgoing <- `{"type":6}`
			o.outgoing <- `{"type":1,"target":"OnMessage","arguments":["Test: <span class=\"ok\">passed</span>"]}`
			o.outgoing <- redirectPopup(o.authorize + "?" + o.authorization().Encode())
		case "OnCallback":
			if o.callbacks++; o.callbacks == 1 {
				o.outgoing <- redirectPopup("/Callback/PostRedirect/" + managerID + "?values=dmFsdWVz")
				break
			}
			o.outgoing <- redirectPopup(o.as.URL + "/invalid")
		case "OnCancel":
			o.outgoing <- redirectPopup("/Callback/Skipped")
			o.outgoing <- `{"type":1,"target":"OnFinished","arguments":["All tests finished"]}`
		}
	}
}

func redirectPopup(u string) string {
	b, _ := json.Marshal(map[string]any{"type": 1, "target": "RedirectPopup", "arguments": []string{u}})
	return string(b)
}

// poll answers a long polling request with the frames waiting for the driver.
func (o *oauch) poll(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("id") != "t1" {
		http.Error(w, "unknown connection", http.StatusNotFound)
		return
	}
	select {
	case f := <-o.outgoing:
		_, _ = io.WriteString(w, f+"\x1e")
	case <-time.After(50 * time.Millisecond):
	case <-r.Context().Done():
	}
}

func (o *oauch) frames() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.invoked...)
}

func TestRunReportsTheTestRun(t *testing.T) {
	as := newAuthorizationServer(t)
	o := newOAuch(t, as)
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), config{oauch: o.URL, issuer: as.URL, out: out, wait: time.Minute}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("got exit status %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	callback := o.URL + "/Callback?code=c0de&state=s+1"
	want := []string{
		`{"protocol":"json","version":1}`,
		fmt.Sprintf("OnReady%q", []string{managerID}),
		fmt.Sprintf("OnCallback%q", []string{managerID, callback, ""}),
		fmt.Sprintf("OnCallback%q", []string{managerID, callback, ""}),
		fmt.Sprintf("OnCancel%q", []string{managerID}),
	}
	if got := o.frames(); !slices.Equal(got, want) {
		t.Errorf("got frames\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	var site []map[string]any
	if err := json.Unmarshal([]byte(o.site), &site); err != nil || len(site) != 1 {
		t.Fatalf("imported site %q: %v", o.site, err)
	}
	settings, _ := json.Marshal(site[0]["CurrentConfiguration"])
	for _, s := range []string{
		`"AuthorizationUri":"` + as.URL + `/authorize"`,
		`"TokenUri":"` + as.URL + `/token"`,
		`"RevocationUri":"` + as.URL + `/revoke"`,
		`"CallbackUri":"` + o.URL + `/Callback"`,
		`"DefaultClient":{"ClientId":"oauch","ClientSecret":"oauch-secret","Scope":"profile"}`,
		`"AlternativeClient":{"ClientId":"oauch-alternative","ClientSecret":"oauch-secret","Scope":"profile"}`,
	} {
		if !strings.Contains(string(settings), s) {
			t.Errorf("site settings %s do not contain %s", settings, s)
		}
	}

	if got := read(t, filepath.Join(out, "export.json")); got != exportJSON {
		t.Errorf("export.json is %q, want the OAuch export", got)
	}
	summary := `# OAuch

5 tests: 1 fully implemented, 0 partially implemented, 1 not implemented, 1 failed, 1 skipped, 1 without an outcome.

## Not implemented

- OAuch.Compliance.Tests.Tokens.RefreshTokenRevokedTest

## Failed

- OAuch.Compliance.Tests.Tokens.TokenEntropyTest

## Stalled

- GET ` + as.URL + `/invalid answered 400 Bad Request without a form
`
	if got := read(t, filepath.Join(out, "summary.md")); got != summary {
		t.Errorf("summary.md is\n%s\nwant\n%s", got, summary)
	}
	if !strings.HasSuffix(stdout.String(), summary) {
		t.Errorf("stdout %q does not end with the summary", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Test: passed\n") {
		t.Errorf("stdout %q does not show the hub's messages without markup", stdout.String())
	}
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name) // #nosec G304 -- name is in the test's temporary directory
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRunFailsWhenTheTestRunFails(t *testing.T) {
	as := newAuthorizationServer(t)
	o := newOAuch(t, as)
	o.fail = "The specified test ID could not be found."
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), config{oauch: o.URL, issuer: as.URL, out: out, wait: time.Minute}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), o.fail) {
		t.Fatalf("got exit status %d and stderr %q, want 1 with the test run's error", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(out, "summary.md")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("got summary.md (%v), want none", err)
	}
}

func TestRunFailsWhenTheAuthorizationServerIsNotReady(t *testing.T) {
	as := newAuthorizationServer(t)
	o := newOAuch(t, as)
	as.Close()
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), config{oauch: o.URL, issuer: as.URL, out: t.TempDir(), wait: 100 * time.Millisecond}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "authorization server: not ready") {
		t.Fatalf("got exit status %d and stderr %q, want 1 saying the Authorization Server is not ready", code, stderr.String())
	}
}

func TestRunFailsWhenTheAuthorizationServerIsUnreachable(t *testing.T) {
	as := newAuthorizationServer(t)
	o := newOAuch(t, as)
	o.authorize = "https://127.0.0.1:1/authorize"
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), config{oauch: o.URL, issuer: as.URL, out: t.TempDir(), wait: time.Minute}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "127.0.0.1:1") {
		t.Fatalf("got exit status %d and stderr %q, want 1 naming the unreachable endpoint", code, stderr.String())
	}
	for _, f := range o.frames() {
		if strings.HasPrefix(f, "OnCancel") {
			t.Errorf("got %s, want the run to stop instead of cancelling the test", f)
		}
	}
}
