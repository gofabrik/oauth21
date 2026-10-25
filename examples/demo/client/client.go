package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/oauth2"
)

//go:embed templates/*.html
var templateFiles embed.FS

var templates = template.Must(template.ParseFS(templateFiles, "templates/*.html"))

type homePage struct {
	Token  *oauth2.Token
	Answer string
}

// metadata is the part of the Authorization Server metadata (RFC 8414) the Client uses.
type metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// discover fetches the metadata of the Authorization Server with the identifier issuer.
func discover(ctx context.Context, httpClient *http.Client, issuer string) (metadata, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return metadata{}, err
	}
	u.Path = "/.well-known/oauth-authorization-server" + u.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return metadata{}, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return metadata{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return metadata{}, fmt.Errorf("metadata: status %d", resp.StatusCode)
	}
	var m metadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return metadata{}, fmt.Errorf("metadata: %w", err)
	}
	if m.Issuer != issuer {
		return metadata{}, errors.New("metadata: issuer does not match")
	}
	return m, nil
}

// client is a public Client that gets tokens with golang.org/x/oauth2 and keeps those of one Resource Owner.
type client struct {
	*http.ServeMux
	oauth          oauth2.Config
	issuer         string
	resourceServer string
	httpClient     *http.Client

	mu sync.Mutex
	// verifiers maps the state of each pending Authorization Request to its PKCE code verifier.
	verifiers map[string]string

	// tokenMu is held while the tokens and the answer are read, used or replaced.
	tokenMu sync.Mutex
	token   *oauth2.Token
	// answer is the last answer of the Resource Server.
	answer string
}

// newClient returns the Client served at clientURL for the Authorization Server with metadata m.
func newClient(m metadata, clientURL, resourceServerURL string, httpClient *http.Client) *client {
	c := &client{
		ServeMux: http.NewServeMux(),
		oauth: oauth2.Config{
			ClientID:    clientID,
			Endpoint:    oauth2.Endpoint{AuthURL: m.AuthorizationEndpoint, TokenURL: m.TokenEndpoint, AuthStyle: oauth2.AuthStyleInParams},
			RedirectURL: clientURL + "/callback",
			Scopes:      []string{scope},
		},
		issuer:         m.Issuer,
		resourceServer: resourceServerURL,
		httpClient:     httpClient,
		verifiers:      map[string]string{},
	}
	c.HandleFunc("GET /{$}", c.home)
	c.HandleFunc("GET /login", c.login)
	c.HandleFunc("GET /callback", c.callback)
	c.HandleFunc("POST /refresh", c.refresh)
	c.HandleFunc("POST /call", c.call)
	return c
}

func (c *client) home(w http.ResponseWriter, _ *http.Request) {
	c.tokenMu.Lock()
	page := homePage{Token: c.token, Answer: c.answer}
	c.tokenMu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "home.html", page); err != nil {
		log.Print(err)
	}
}

func (c *client) login(w http.ResponseWriter, r *http.Request) {
	state, verifier := rand.Text(), oauth2.GenerateVerifier()
	c.mu.Lock()
	c.verifiers[state] = verifier
	c.mu.Unlock()
	http.SetCookie(w, stateCookie(state, 0))
	http.Redirect(w, r, c.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// stateCookie returns the cookie that binds state to the browser, deleted when maxAge is negative.
func stateCookie(state string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: "state", Value: state, Path: "/callback", MaxAge: maxAge, HttpOnly: true, SameSite: http.SameSiteLaxMode} // #nosec G124 -- the Client is served over HTTP on a loopback address
}

func (c *client) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	cookie, err := r.Cookie("state")
	http.SetCookie(w, stateCookie("", -1))
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "state does not match", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	verifier, ok := c.verifiers[state]
	delete(c.verifiers, state)
	c.mu.Unlock()
	switch {
	case !ok:
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	case q.Get("iss") != c.issuer:
		http.Error(w, "issuer does not match", http.StatusBadRequest)
		return
	case q.Has("error"):
		http.Error(w, "authorization failed: "+q.Get("error"), http.StatusForbidden)
		return
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	token, err := c.oauth.Exchange(c.context(r), q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		log.Print(err)
		http.Error(w, "token request failed", http.StatusBadGateway)
		return
	}
	c.replaceToken(w, r, token)
}

func (c *client) refresh(w http.ResponseWriter, r *http.Request) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.token == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	token, err := c.oauth.TokenSource(c.context(r), &oauth2.Token{RefreshToken: c.token.RefreshToken}).Token()
	if err != nil {
		log.Print(err)
		http.Error(w, "refresh failed", http.StatusBadGateway)
		return
	}
	c.replaceToken(w, r, token)
}

// replaceToken replaces the tokens with token, with tokenMu held, and redirects to the home page.
func (c *client) replaceToken(w http.ResponseWriter, r *http.Request, token *oauth2.Token) {
	c.token, c.answer = token, ""
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (c *client) call(w http.ResponseWriter, r *http.Request) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.token == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	answer, err := c.callResourceServer(r.Context(), c.token)
	if err != nil {
		log.Print(err)
		http.Error(w, "resource server request failed", http.StatusBadGateway)
		return
	}
	c.answer = answer
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// callResourceServer calls the Resource Server with token and returns the status and body of its answer.
func (c *client) callResourceServer(ctx context.Context, token *oauth2.Token) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.resourceServer, nil)
	if err != nil {
		return "", err
	}
	token.SetAuthHeader(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if err != nil {
		return "", err
	}
	return resp.Status + ": " + strings.TrimSpace(string(body)), nil
}

// context returns the context of r with the HTTP client that x/oauth2 uses.
func (c *client) context(r *http.Request) context.Context {
	return context.WithValue(r.Context(), oauth2.HTTPClient, c.httpClient)
}
