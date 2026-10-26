// Command oauch runs an OAuch test run against the example Authorization Server and writes its export and a summary.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

// The Resource Owner and the Clients the example Authorization Server registers for OAuch.
const (
	username            = "demo"
	password            = "demo"
	scope               = "profile"
	clientID            = "oauch"
	alternativeClientID = "oauch-alternative"
	clientSecret        = "oauch-secret" // #nosec G101 -- the secret of the example's OAuch Clients
)

// standards are the OAuch documents the test run checks: OAuth 2.0 with the Security BCP, PKCE and revocation.
var standards = []string{"RFC6749", "RFC6750", "RFC6819", "SecBCP", "RFC7636", "RFC7009"}

// excludedFlows are the OAuch flows the Authorization Server does not offer.
var excludedFlows = []string{
	"token", "id_token token", "id_token", "code id_token", "code token", "code id_token token",
	"urn:ietf:params:oauth:grant-type:device_code", "password",
}

// OAuch settings by value.
const (
	clientSecretBasic = 0
	pkceHashed        = 2
)

// OAuch test outcomes by value.
const (
	fullyImplemented = iota
	notImplemented
	partiallyImplemented
	skipped
	failed
)

// outcomes are the names of the OAuch test outcomes by value.
var outcomes = []string{"fully implemented", "not implemented", "partially implemented", "skipped", "failed"}

type config struct {
	oauch, issuer, out string
	wait               time.Duration
}

func main() {
	var c config
	flag.StringVar(&c.oauch, "oauch", "https://127.0.0.1", "URL of OAuch")
	flag.StringVar(&c.issuer, "issuer", "https://127.0.0.1:9000", "issuer identifier of the Authorization Server")
	flag.StringVar(&c.out, "out", "oauch-results", "directory to write export.json and summary.md to")
	flag.DurationVar(&c.wait, "wait", 2*time.Minute, "how long to wait for OAuch and the Authorization Server to start")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, c, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run imports the Authorization Server into OAuch, runs its tests and writes the results to c.out, and returns the exit status.
func run(ctx context.Context, c config, stdout, stderr io.Writer) int {
	if err := testRun(ctx, c, stdout); err != nil {
		_, _ = fmt.Fprintln(stderr, "oauch:", err)
		return 1
	}
	return 0
}

func testRun(ctx context.Context, c config, stdout io.Writer) error {
	base, err := url.Parse(c.oauch)
	if err != nil {
		return err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Jar:           jar,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // #nosec G402 -- OAuch and the example Authorization Server have self-signed certificates
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()

	var metadata struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		RevocationEndpoint    string `json:"revocation_endpoint"`
	}
	metadataURL := c.issuer + "/.well-known/oauth-authorization-server"
	err = await(ctx, c.wait, func(ctx context.Context) error {
		b, err := do(ctx, client, http.MethodGet, metadataURL, "", nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(b, &metadata)
	})
	if err != nil {
		return fmt.Errorf("authorization server: %w", err)
	}
	if err := await(ctx, c.wait, func(ctx context.Context) error {
		_, err := do(ctx, client, http.MethodGet, c.oauch+"/", "", nil)
		return err
	}); err != nil {
		return fmt.Errorf("oauch: %w", err)
	}

	site, err := json.Marshal([]siteData{{Name: "oauth21", CurrentConfiguration: siteSettings{
		SelectedStandards:             standards,
		MetadataURI:                   metadataURL,
		AuthorizationURI:              metadata.AuthorizationEndpoint,
		TokenURI:                      metadata.TokenEndpoint,
		RevocationURI:                 metadata.RevocationEndpoint,
		CallbackURI:                   c.oauch + "/Callback",
		DefaultClient:                 clientSettings{ClientID: clientID, ClientSecret: clientSecret, Scope: scope},
		AlternativeClient:             clientSettings{ClientID: alternativeClientID, ClientSecret: clientSecret, Scope: scope},
		PKCEDefault:                   pkceHashed,
		ClientAuthenticationMechanism: clientSecretBasic,
		ExcludedFlows:                 excludedFlows,
	}}})
	if err != nil {
		return err
	}
	siteID, err := importSite(ctx, client, c.oauch, site)
	if err != nil {
		return err
	}
	running, err := do(ctx, client, http.MethodGet, c.oauch+"/Dashboard/Running/"+siteID, "", nil)
	if err != nil {
		return err
	}
	m := regexp.MustCompile(`var testId = "([^"]+)"`).FindSubmatch(running)
	if m == nil {
		return errors.New("the running page has no test run")
	}
	managerID := string(m[1])

	h, err := dialHub(ctx, client, c.oauch)
	if err != nil {
		return err
	}
	if err := h.invoke(ctx, "OnReady", managerID); err != nil {
		return err
	}
	p := &popup{client: client, oauch: base, fill: url.Values{"username": {username}, "password": {password}, "decision": {"allow"}}}
	stalls, err := follow(ctx, h, p, managerID, stdout)
	if err != nil {
		return err
	}

	export, err := do(ctx, client, http.MethodGet, c.oauch+"/Dashboard/ExportData/"+siteID, "", nil)
	if err != nil {
		return err
	}
	summary, err := summarize(export, stalls)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.out, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.out, "export.json"), export, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.out, "summary.md"), []byte(summary), 0o600); err != nil {
		return err
	}
	_, err = io.WriteString(stdout, summary)
	return err
}

// await calls ready until it succeeds, waiting at most timeout.
func await(ctx context.Context, timeout time.Duration, ready func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		err := ready(ctx)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("not ready within %v: %w", timeout, err)
		case <-tick.C:
		}
	}
}

// importSite imports the site export site into OAuch and returns its identifier.
func importSite(ctx context.Context, client *http.Client, base string, site []byte) (string, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", "site.json")
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(site); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}
	if _, err := do(ctx, client, http.MethodPost, base+"/Dashboard/Import", mw.FormDataContentType(), &body); err != nil {
		return "", err
	}
	dashboard, err := do(ctx, client, http.MethodGet, base+"/Dashboard", "", nil)
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`(?i)/Dashboard/Results/([0-9a-f-]{36})`).FindSubmatch(dashboard)
	if m == nil {
		return "", errors.New("the dashboard lists no site after the import")
	}
	return string(m[1]), nil
}

// do sends a request and returns the body of its successful response.
func do(ctx context.Context, client *http.Client, method, u, contentType string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, fmt.Errorf("%s %s: no content", method, req.URL.Path)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s %s: %s", method, req.URL.Path, resp.Status)
	}
	return b, nil
}

// follow plays the pop-up for the hub until the test run finishes, and returns the reasons of the tests it cancelled as stalled.
func follow(ctx context.Context, h *hub, p *popup, managerID string, stdout io.Writer) ([]string, error) {
	markup := regexp.MustCompile(`<[^>]*>`)
	var stalls []string
	for {
		msgs, err := h.poll(ctx)
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Error != "" {
				return nil, fmt.Errorf("hub: %s", m.Error)
			}
			if m.Type == closeMessage {
				return nil, errors.New("the hub closed the connection before the test run finished")
			}
			if m.Type != invocationMessage {
				continue
			}
			var arg string
			if len(m.Arguments) > 0 {
				_ = json.Unmarshal(m.Arguments[0], &arg)
			}
			switch m.Target {
			case "OnMessage":
				_, _ = fmt.Fprintln(stdout, markup.ReplaceAllString(arg, ""))
			case "OnError":
				return nil, fmt.Errorf("test run: %s", arg)
			case "OnFinished":
				_, _ = fmt.Fprintln(stdout, arg)
				return stalls, nil
			case "RedirectPopup":
				cb, err := p.open(ctx, arg)
				var st *stall
				switch {
				case errors.As(err, &st):
					_, _ = fmt.Fprintln(stdout, "stalled:", st)
					stalls = append(stalls, st.reason)
					err = h.invoke(ctx, "OnCancel", managerID)
				case err != nil:
					return nil, err
				case cb != nil:
					err = h.invoke(ctx, "OnCallback", managerID, cb.href, cb.form)
				}
				if err != nil {
					return nil, err
				}
			}
		}
	}
}

type siteData struct {
	Name                 string
	CurrentConfiguration siteSettings
}

type siteSettings struct {
	SelectedStandards             []string
	MetadataURI                   string `json:"MetadataUri"`
	AuthorizationURI              string `json:"AuthorizationUri"`
	TokenURI                      string `json:"TokenUri"`
	RevocationURI                 string `json:"RevocationUri"`
	CallbackURI                   string `json:"CallbackUri"`
	DefaultClient                 clientSettings
	AlternativeClient             clientSettings
	PKCEDefault                   int
	ClientAuthenticationMechanism int
	ExcludedFlows                 []string
}

type clientSettings struct {
	ClientID     string `json:"ClientId"`
	ClientSecret string
	Scope        string
}

// summarize returns the Markdown summary of the last test run in the OAuch export and of the stalls.
func summarize(export []byte, stalls []string) (string, error) {
	var sites []struct {
		TestRuns []struct {
			TestResults []struct {
				TestID  string `json:"TestId"`
				Outcome *int
			}
		}
	}
	if err := json.Unmarshal(export, &sites); err != nil {
		return "", fmt.Errorf("export: %w", err)
	}
	if len(sites) != 1 || len(sites[0].TestRuns) == 0 {
		return "", errors.New("export: no test run")
	}
	latest := sites[0].TestRuns[len(sites[0].TestRuns)-1]
	byOutcome := make([][]string, len(outcomes))
	var unknown int
	for _, r := range latest.TestResults {
		if r.Outcome == nil || *r.Outcome < 0 || *r.Outcome >= len(outcomes) {
			unknown++
			continue
		}
		byOutcome[*r.Outcome] = append(byOutcome[*r.Outcome], r.TestID)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# OAuch\n\n%d tests: %d fully implemented, %d partially implemented, %d not implemented, %d failed, %d skipped",
		len(latest.TestResults), len(byOutcome[fullyImplemented]), len(byOutcome[partiallyImplemented]),
		len(byOutcome[notImplemented]), len(byOutcome[failed]), len(byOutcome[skipped]))
	if unknown > 0 {
		fmt.Fprintf(&b, ", %d without an outcome", unknown)
	}
	b.WriteString(".\n")
	for _, o := range []int{notImplemented, partiallyImplemented, failed} {
		if len(byOutcome[o]) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s\n\n", strings.ToUpper(outcomes[o][:1])+outcomes[o][1:])
		slices.Sort(byOutcome[o])
		for _, id := range byOutcome[o] {
			fmt.Fprintf(&b, "- %s\n", id)
		}
	}
	if len(stalls) > 0 {
		b.WriteString("\n## Stalled\n\n")
		for _, reason := range stalls {
			fmt.Fprintf(&b, "- %s\n", reason)
		}
	}
	return b.String(), nil
}
