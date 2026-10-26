package main

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// maxSteps is how many redirects and form submissions the pop-up follows before it counts as stalled.
const maxSteps = 20

// popup plays the pop-up window of an OAuch test run: it follows redirects and submits forms until it reaches the OAuch callback.
type popup struct {
	client *http.Client
	oauch  *url.URL
	// fill are the values the pop-up enters into the form controls of these names.
	fill url.Values
}

// stall is the reason the pop-up stops before the callback on a page a user could only leave with the "Stalled test" button.
type stall struct {
	reason string
}

func (s *stall) Error() string {
	return s.reason
}

// callback is what the OAuch callback page reports to the test run.
type callback struct {
	href, form string
}

// step is a request of the pop-up.
type step struct {
	method string
	url    *url.URL
	form   url.Values
}

// open loads target, which is relative to OAuch, and returns the callback the pop-up reaches, or nil for an OAuch page that reports nothing.
func (p *popup) open(ctx context.Context, target string) (*callback, error) {
	u, err := p.oauch.Parse(target)
	if err != nil {
		return nil, err
	}
	s := step{method: http.MethodGet, url: u}
	for range maxSteps {
		if s.url.Scheme == p.oauch.Scheme && s.url.Host == p.oauch.Host {
			path := strings.ToLower(s.url.Path)
			switch {
			case strings.HasPrefix(path, "/callback/initial"), strings.HasPrefix(path, "/callback/skipped"):
				return nil, nil
			case !strings.HasPrefix(path, "/callback/postredirect"):
				return &callback{href: s.url.String(), form: s.form.Encode()}, nil
			}
		}
		next, err := p.load(ctx, s)
		if err != nil {
			return nil, err
		}
		s = next
	}
	return nil, &stall{fmt.Sprintf("no callback after %d steps from %s", maxSteps, u.Redacted())}
}

// load sends s and returns the step that follows from its response.
func (p *popup) load(ctx context.Context, s step) (step, error) {
	var body io.Reader
	if s.method == http.MethodPost {
		body = strings.NewReader(s.form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, s.method, s.url.String(), body)
	if err != nil {
		return step{}, err
	}
	if s.method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return step{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	page, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return step{}, err
	}
	if loc := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
		next, err := s.url.Parse(loc)
		if err != nil {
			return step{}, err
		}
		return step{method: http.MethodGet, url: next}, nil
	}
	f, ok := parseForm(string(page))
	if resp.StatusCode != http.StatusOK || !ok {
		return step{}, &stall{fmt.Sprintf("%s %s answered %s without a form", s.method, s.url.Redacted(), resp.Status)}
	}
	return p.submit(s.url, f)
}

// submit fills f, found on the page at base, and returns its submission.
func (p *popup) submit(base *url.URL, f form) (step, error) {
	action, err := base.Parse(f.action)
	if err != nil {
		return step{}, err
	}
	for name, values := range p.fill {
		if f.controls[name] {
			f.values[name] = values
		}
	}
	if strings.EqualFold(f.method, http.MethodPost) {
		return step{method: http.MethodPost, url: action, form: f.values}, nil
	}
	action.RawQuery = f.values.Encode()
	return step{method: http.MethodGet, url: action}, nil
}

// form is the first HTML form of a page.
type form struct {
	action, method string
	// values are the values of the form's inputs.
	values url.Values
	// controls are the names of the form's inputs and buttons.
	controls map[string]bool
}

var (
	formPattern    = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)(?:</form>|$)`)
	controlPattern = regexp.MustCompile(`(?is)<(input|button)\b([^>]*)>`)
	attrPattern    = regexp.MustCompile(`(?s)([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+)))?`)
)

// parseForm returns the first form of page.
func parseForm(page string) (form, bool) {
	m := formPattern.FindStringSubmatch(page)
	if m == nil {
		return form{}, false
	}
	attrs := parseAttrs(m[1])
	f := form{action: attrs["action"], method: attrs["method"], values: url.Values{}, controls: map[string]bool{}}
	for _, c := range controlPattern.FindAllStringSubmatch(m[2], -1) {
		attrs := parseAttrs(c[2])
		name := attrs["name"]
		if name == "" {
			continue
		}
		f.controls[name] = true
		switch strings.ToLower(attrs["type"]) {
		case "submit", "button", "image", "reset":
			continue
		}
		if strings.EqualFold(c[1], "input") {
			f.values.Add(name, attrs["value"])
		}
	}
	return f, true
}

// parseAttrs returns the attributes of the tag contents s by lowercase name.
func parseAttrs(s string) map[string]string {
	attrs := map[string]string{}
	for _, a := range attrPattern.FindAllStringSubmatch(s, -1) {
		name := strings.ToLower(a[1])
		if _, ok := attrs[name]; !ok {
			attrs[name] = html.UnescapeString(a[2] + a[3] + a[4])
		}
	}
	return attrs
}
