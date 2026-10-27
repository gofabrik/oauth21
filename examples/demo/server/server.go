package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/memstore"
	"github.com/gofabrik/oauth21/store"
)

//go:embed templates/*.html
var templateFiles embed.FS

var templates = template.Must(template.ParseFS(templateFiles, "templates/*.html"))

type loginPage struct {
	RequestID string
	Error     string
}

type consentPage struct {
	RequestID string
	ClientID  string
	Scopes    []string
	Subject   string
}

// authorizationServer is the Host Application of the Authorization Server, with login and consent pages for one Resource Owner.
type authorizationServer struct {
	*http.ServeMux
	oauth *oauth21.Server

	mu sync.Mutex
	// logins maps the values of login cookies to the subject logged in.
	logins map[string]string
}

// newAuthorizationServer returns an Authorization Server with the identifier issuer, the supported scopes and the registered clients.
func newAuthorizationServer(issuer string, scopes []string, clients ...store.Client) (*authorizationServer, error) {
	st := memstore.New()
	for _, c := range clients {
		st.AddClient(c)
	}
	oauth, err := oauth21.New(oauth21.Config{
		Issuer:                issuer,
		LoginURL:              issuer + "/login",
		Clients:               st,
		AuthorizationRequests: st,
		Codes:                 st,
		Tokens:                st,
		Scopes:                scopes,
	})
	if err != nil {
		return nil, err
	}
	srv := &authorizationServer{ServeMux: http.NewServeMux(), oauth: oauth, logins: map[string]string{}}
	p := oauth.Paths()
	srv.Handle(oauth.MetadataPath(), oauth.MetadataHandler())
	srv.Handle(p.Authorization, oauth.AuthorizationHandler())
	srv.Handle(p.Token, oauth.TokenHandler())
	srv.Handle(p.Revocation, oauth.RevocationHandler())
	srv.Handle(p.Introspection, oauth.IntrospectionHandler())
	srv.HandleFunc("GET /login", srv.showLogin)
	srv.HandleFunc("POST /login", srv.login)
	srv.HandleFunc("GET /consent", srv.showConsent)
	srv.HandleFunc("POST /consent", srv.consent)
	return srv, nil
}

func (s *authorizationServer) showLogin(w http.ResponseWriter, r *http.Request) {
	render(w, http.StatusOK, "login.html", loginPage{RequestID: r.FormValue("request_id")})
}

func (s *authorizationServer) login(w http.ResponseWriter, r *http.Request) {
	requestID := r.PostFormValue("request_id")
	if !equal(r.PostFormValue("username"), username) || !equal(r.PostFormValue("password"), password) {
		render(w, http.StatusUnauthorized, "login.html", loginPage{RequestID: requestID, Error: "Wrong username or password."})
		return
	}
	login := rand.Text()
	s.mu.Lock()
	s.logins[login] = username
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "login", Value: login, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/consent?"+url.Values{"request_id": {requestID}}.Encode(), http.StatusSeeOther)
}

func (s *authorizationServer) showConsent(w http.ResponseWriter, r *http.Request) {
	subject, req, ok := s.pending(w, r)
	if !ok {
		return
	}
	render(w, http.StatusOK, "consent.html", consentPage{RequestID: req.ID, ClientID: req.Client.ID, Scopes: req.Scopes, Subject: subject})
}

func (s *authorizationServer) consent(w http.ResponseWriter, r *http.Request) {
	subject, req, ok := s.pending(w, r)
	if !ok {
		return
	}
	var loc string
	var err error
	if r.PostFormValue("decision") == "allow" {
		loc, err = s.oauth.Complete(r.Context(), req.ID, oauth21.Completion{Subject: subject, Scopes: req.Scopes})
	} else {
		loc, err = s.oauth.Deny(r.Context(), req.ID)
	}
	if err != nil {
		authorizationError(w, err)
		return
	}
	http.Redirect(w, r, loc, http.StatusSeeOther) // #nosec G710 -- loc is the registered redirect URI of the Client
}

// pending returns the subject logged in with r and the pending Authorization Request named by r, or writes the error response.
func (s *authorizationServer) pending(w http.ResponseWriter, r *http.Request) (string, oauth21.AuthorizationRequest, bool) {
	subject, ok := s.subject(r)
	if !ok {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return "", oauth21.AuthorizationRequest{}, false
	}
	req, err := s.oauth.AuthorizationRequest(r.Context(), r.FormValue("request_id"))
	if err != nil {
		authorizationError(w, err)
		return "", oauth21.AuthorizationRequest{}, false
	}
	return subject, req, true
}

// subject returns the subject logged in with the login cookie of r.
func (s *authorizationServer) subject(r *http.Request) (string, bool) {
	c, err := r.Cookie("login")
	if err != nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	subject, ok := s.logins[c.Value]
	return subject, ok
}

// equal reports whether a and b are equal, in time that does not depend on their contents.
func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func authorizationError(w http.ResponseWriter, err error) {
	if errors.Is(err, oauth21.ErrRequestNotPending) || errors.Is(err, oauth21.ErrInvalidCompletion) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Print(err)
	http.Error(w, "server error", http.StatusInternalServerError)
}

func render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	oauth21.ProtectFraming(w.Header())
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Print(err)
	}
}
