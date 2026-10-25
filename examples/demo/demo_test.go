// Package demo runs the full flow against the running demo programs.
package demo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// demo is the running demo as a browser sees it.
type demo struct {
	t         *testing.T
	clientURL string
	browser   *http.Client
}

// start builds the Authorization Server, the Client and the Resource Server and runs each in its own process, on other ports when they do not start.
func start(t *testing.T) *demo {
	t.Helper()
	bin := t.TempDir()
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin+string(filepath.Separator), "./server", "./client", "./resourceserver") // #nosec G204 -- bin is the test's temporary directory
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	ca := filepath.Join(bin, "demo-ca.pem")
	for range 3 {
		if clientURL, ok := run(t, bin, ca); ok {
			return &demo{t: t, clientURL: clientURL, browser: browser(t, ca)}
		}
	}
	t.Fatal("the demo did not start")
	return nil
}

// run runs the programs in bin on free loopback ports until the test ends, and returns the URL of the Client.
func run(t *testing.T, bin, ca string) (string, bool) {
	t.Helper()
	_ = os.Remove(ca)
	asAddr, clientAddr, rsAddr := freeAddr(t), freeAddr(t), freeAddr(t)
	server := launch(t, filepath.Join(bin, "server"), "-addr", asAddr, "-cert-out", ca)
	if !waitFor(func() bool { return exists(ca) }, server) {
		_ = server.stop()
		return "", false
	}
	rs := launch(t, filepath.Join(bin, "resourceserver"), "-addr", rsAddr, "-introspection-endpoint", "https://"+asAddr+"/introspect", "-ca", ca)
	client := launch(t, filepath.Join(bin, "client"), "-addr", clientAddr, "-issuer", "https://"+asAddr, "-ca", ca, "-resource-server", "http://"+rsAddr+"/hello")
	programs := []*program{client, rs, server}
	clientReady := func(_ *http.Response, page string) bool { return strings.Contains(page, "<h1>Client</h1>") }
	rsReady := func(resp *http.Response, _ string) bool {
		return strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), `Bearer realm="oauth21"`)
	}
	ready := func() bool {
		return serving(t, "http://"+rsAddr+"/hello", rsReady) && serving(t, "http://"+clientAddr, clientReady)
	}
	if !waitFor(ready, programs...) {
		for _, p := range programs {
			_ = p.stop()
		}
		return "", false
	}
	t.Cleanup(func() {
		for _, p := range programs {
			if err := p.stop(); err != nil {
				t.Errorf("%s: %v", p.name, err)
			}
		}
	})
	return "http://" + clientAddr, true
}

// browser returns an HTTP client with a cookie jar that trusts the certificate in the PEM file ca.
func browser(t *testing.T, ca string) *http.Client {
	t.Helper()
	data, err := os.ReadFile(ca) // #nosec G304 -- the file is in the test's temporary directory
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		t.Fatal("no certificate in", ca)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	t.Cleanup(transport.CloseIdleConnections)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: transport, Jar: jar}
}

// program is a demo program running in its own process.
type program struct {
	name   string
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

// launch starts the program name with args, which is stopped at the latest when the test ends.
func launch(t *testing.T, name string, args ...string) *program {
	t.Helper()
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- the programs are built by the test
	cmd.Stdout, cmd.Stderr = t.Output(), t.Output()
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	p := &program{name: filepath.Base(name), cancel: cancel, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() { _ = p.stop() })
	return p
}

// stop interrupts p, waits for it to exit, and returns its error unless it exited cleanly when interrupted.
func (p *program) stop() error {
	p.cancel()
	<-p.done
	if errors.Is(p.err, context.Canceled) {
		return nil
	}
	return p.err
}

// waitFor waits at most 30 seconds until ready, and reports false as soon as one of programs exits.
func waitFor(ready func() bool, programs ...*program) bool {
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		for _, p := range programs {
			select {
			case <-p.done:
				return false
			default:
			}
		}
		if ready() {
			return true
		}
		select {
		case <-timeout.C:
			return false
		case <-tick.C:
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// serving reports whether a GET of target gets a response and page that are ours.
func serving(t *testing.T, target string, ours func(*http.Response, string) bool) bool {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	client := http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	page, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return err == nil && ours(resp, string(page))
}

func exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// response is the final response to a request after redirects.
type response struct {
	status int
	url    *url.URL
	page   string
}

// send sends a request with method to target, with form as the body of a POST, and returns the final response after redirects.
func (d *demo) send(method, target string, form url.Values) (response, error) {
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(d.t.Context(), method, target, body)
	if err != nil {
		return response{}, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := d.browser.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	page, err := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, url: resp.Request.URL, page: string(page)}, err
}

// get sends a GET to target and returns the final URL and page, failing the test unless the status is 200.
func (d *demo) get(target string) (*url.URL, string) {
	d.t.Helper()
	return d.ok(d.send(http.MethodGet, target, nil))
}

// post sends a POST of form to target and returns the final URL and page, failing the test unless the status is 200.
func (d *demo) post(target string, form url.Values) (*url.URL, string) {
	d.t.Helper()
	return d.ok(d.send(http.MethodPost, target, form))
}

// ok returns the final URL and page of resp, failing the test on err or unless the status is 200.
func (d *demo) ok(resp response, err error) (*url.URL, string) {
	d.t.Helper()
	if err != nil {
		d.t.Fatal(err)
	}
	if resp.status != http.StatusOK {
		d.t.Fatalf("%s: status %d: %s", resp.url, resp.status, resp.page)
	}
	return resp.url, resp.page
}

// authorize logs in as the demo Resource Owner, allows the Client, and returns the Client's page.
func (d *demo) authorize() string {
	d.t.Helper()
	login, _ := d.get(d.clientURL + "/login")
	requestID := login.Query().Get("request_id")
	consent, _ := d.post(login.String(), url.Values{"request_id": {requestID}, "username": {"demo"}, "password": {"demo"}})
	_, page := d.post(consent.String(), url.Values{"request_id": {requestID}, "decision": {"allow"}})
	return page
}

// call has the Client call the Resource Server, failing the test unless it answers for the demo Resource Owner.
func (d *demo) call() {
	d.t.Helper()
	_, page := d.post(d.clientURL+"/call", nil)
	if got, want := field(d.t, page, "resource"), "200 OK: Hello, demo. Scopes: profile."; got != want {
		d.t.Errorf("resource = %q, want %q", got, want)
	}
}

func field(t *testing.T, page, id string) string {
	t.Helper()
	m := regexp.MustCompile(`id="` + id + `">([^<]*)<`).FindStringSubmatch(page)
	if m == nil || m[1] == "" {
		t.Fatalf("page has no %s:\n%s", id, page)
	}
	return m[1]
}

func TestFlow(t *testing.T) {
	d := start(t)
	page := d.authorize()
	access, refresh := field(t, page, "access-token"), field(t, page, "refresh-token")
	if scope := field(t, page, "scope"); scope != "profile" {
		t.Errorf("scope = %q, want profile", scope)
	}

	_, page = d.post(d.clientURL+"/refresh", nil)
	if field(t, page, "access-token") == access || field(t, page, "refresh-token") == refresh {
		t.Errorf("refresh kept the tokens:\n%s", page)
	}

	d.call()
}

func TestConcurrentRefresh(t *testing.T) {
	d := start(t)
	d.authorize()
	var wg sync.WaitGroup
	statuses := make(chan int, 5)
	for range cap(statuses) {
		wg.Go(func() {
			resp, err := d.send(http.MethodPost, d.clientURL+"/refresh", nil)
			if err != nil {
				t.Error(err)
				return
			}
			statuses <- resp.status
		})
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Errorf("refresh status = %d, want %d", status, http.StatusOK)
		}
	}

	d.call()
}
