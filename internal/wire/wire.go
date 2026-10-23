package wire

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// ServerError is the error code for a failure inside the Authorization Server.
const ServerError = "server_error"

// OAuth error codes wire produces or answers differently.
const (
	invalidRequest = "invalid_request"
	invalidClient  = "invalid_client"
)

// Error is an OAuth error response.
type Error struct {
	Code        string
	Description string
}

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// Status returns the HTTP status of e when it carries no authentication challenge.
func (e *Error) Status() int {
	if e.Code == ServerError {
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}

// Challenge returns the scheme of the Authorization header of r to challenge with, or "" without one.
func Challenge(r *http.Request) string {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return ""
	}
	scheme, _, _ := strings.Cut(authorization, " ")
	if scheme == "" || strings.IndexFunc(scheme, func(c rune) bool { return !tokenChar(c) }) >= 0 {
		return "Basic"
	}
	return scheme
}

// tokenChar reports whether c may appear in an HTTP token (RFC 9110).
func tokenChar(c rune) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)
}

// AuthorizationParams is the parameters of an authorization request.
type AuthorizationParams struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// ParseAuthorizationParams reads an authorization request from a GET query or a POST form body.
func ParseAuthorizationParams(r *http.Request) (AuthorizationParams, *Error) {
	var params url.Values
	switch r.Method {
	case http.MethodGet:
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return AuthorizationParams{}, &Error{invalidRequest, "malformed query"}
		}
		params = q
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return AuthorizationParams{}, &Error{invalidRequest, "malformed form body"}
		}
		params = r.PostForm
	default:
		return AuthorizationParams{}, &Error{invalidRequest, "method not allowed"}
	}
	var req AuthorizationParams
	err := assignOnce(params, req.fields())
	return req, err
}

func (p *AuthorizationParams) fields() map[string]*string {
	return map[string]*string{
		"response_type":         &p.ResponseType,
		"client_id":             &p.ClientID,
		"redirect_uri":          &p.RedirectURI,
		"state":                 &p.State,
		"scope":                 &p.Scope,
		"code_challenge":        &p.CodeChallenge,
		"code_challenge_method": &p.CodeChallengeMethod,
	}
}

// TokenRequest is the parameters of a token request.
type TokenRequest struct {
	GrantType     string
	Code          string
	RedirectURI   string
	ClientID      string
	CodeVerifier  string
	ClientSecret  string
	Authorization string
}

// ParseTokenRequest reads a token request from the form body of a POST.
func ParseTokenRequest(r *http.Request) (TokenRequest, *Error) {
	if r.Method != http.MethodPost {
		return TokenRequest{}, &Error{invalidRequest, "method not allowed"}
	}
	if err := r.ParseForm(); err != nil {
		return TokenRequest{}, &Error{invalidRequest, "malformed form body"}
	}
	var req TokenRequest
	err := assignOnce(r.PostForm, req.fields())
	req.Authorization = r.Header.Get("Authorization")
	return req, err
}

func (r *TokenRequest) fields() map[string]*string {
	return map[string]*string{
		"grant_type":    &r.GrantType,
		"code":          &r.Code,
		"redirect_uri":  &r.RedirectURI,
		"client_id":     &r.ClientID,
		"code_verifier": &r.CodeVerifier,
		"client_secret": &r.ClientSecret,
	}
}

// assignOnce sets each field to its parameter; empty values count as omitted, and a parameter may appear once.
func assignOnce(params url.Values, fields map[string]*string) *Error {
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		field := fields[name]
		for _, v := range params[name] {
			if v == "" {
				continue
			}
			if *field != "" {
				return &Error{invalidRequest, "repeated parameter " + name}
			}
			*field = v
		}
	}
	return nil
}

// TokenResponse is a successful token response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// WriteToken writes a successful token response.
func WriteToken(w http.ResponseWriter, resp TokenResponse) {
	writeJSON(w, http.StatusOK, resp)
}

// WriteTokenError writes a token endpoint error, as a 401 with challenge for invalid_client when challenge is set.
func WriteTokenError(w http.ResponseWriter, e *Error, challenge string) {
	status := e.Status()
	if e.Code == invalidClient && challenge != "" {
		status = http.StatusUnauthorized
		if strings.EqualFold(challenge, "Basic") {
			challenge += ` realm="oauth21"`
		}
		w.Header().Set("WWW-Authenticate", challenge)
	}
	writeJSON(w, status, struct {
		Error       string `json:"error"`
		Description string `json:"error_description,omitempty"`
	}{e.Code, e.Description})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Redirect returns base with the non-empty params appended to its query.
func Redirect(base string, params url.Values) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	for name, values := range params {
		for _, v := range values {
			if v != "" {
				q.Add(name, v)
			}
		}
	}
	if u.RawQuery != "" {
		u.RawQuery += "&"
	}
	u.RawQuery += q.Encode()
	return u.String(), nil
}

// AuthorizationResponse is where an authorization response goes and the state and issuer it carries.
type AuthorizationResponse struct {
	RedirectURI string
	State       string
	Issuer      string
}

// Code returns the redirect carrying code.
func (a AuthorizationResponse) Code(code string) (string, error) {
	return a.redirect(url.Values{"code": {code}})
}

// Error returns the redirect carrying e.
func (a AuthorizationResponse) Error(e *Error) (string, error) {
	return a.redirect(url.Values{"error": {e.Code}, "error_description": {e.Description}})
}

func (a AuthorizationResponse) redirect(params url.Values) (string, error) {
	params.Set("state", a.State)
	params.Set("iss", a.Issuer)
	return Redirect(a.RedirectURI, params)
}
