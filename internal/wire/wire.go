package wire

import (
	"encoding/base64"
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
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	RefreshToken string
	Scope        string
}

func (r *TokenRequest) fields() map[string]*string {
	return map[string]*string{
		"grant_type":    &r.GrantType,
		"code":          &r.Code,
		"redirect_uri":  &r.RedirectURI,
		"code_verifier": &r.CodeVerifier,
		"refresh_token": &r.RefreshToken,
		"scope":         &r.Scope,
	}
}

// Credentials is how a request identifies and authenticates its Client.
type Credentials struct {
	ClientID     string
	ClientSecret string
	// AuthScheme is the scheme of the Authorization header, or "" without one.
	AuthScheme  string
	BasicID     string
	BasicSecret string
}

func (c *Credentials) fields() map[string]*string {
	return map[string]*string{
		"client_id":     &c.ClientID,
		"client_secret": &c.ClientSecret,
	}
}

// ParseTokenRequest reads a token request from the form body of a POST and the Client credentials of its Authorization header.
func ParseTokenRequest(r *http.Request) (TokenRequest, Credentials, *Error) {
	var req TokenRequest
	c, err := parseClientRequest(r, req.fields())
	if err != nil {
		return TokenRequest{}, Credentials{}, err
	}
	return req, c, nil
}

// ParseRevocationRequest reads the token of a revocation request from the form body of a POST, ignoring the value of token_type_hint, and the Client credentials of its Authorization header.
func ParseRevocationRequest(r *http.Request) (string, Credentials, *Error) {
	var token, hint string
	c, err := parseClientRequest(r, map[string]*string{"token": &token, "token_type_hint": &hint})
	if err != nil {
		return "", Credentials{}, err
	}
	return token, c, nil
}

// parseClientRequest reads the form body of a POST into fields and returns the Client credentials of the body and the Authorization header.
func parseClientRequest(r *http.Request, fields map[string]*string) (Credentials, *Error) {
	if r.Method != http.MethodPost {
		return Credentials{}, &Error{invalidRequest, "method not allowed"}
	}
	if err := r.ParseForm(); err != nil {
		return Credentials{}, &Error{invalidRequest, "malformed form body"}
	}
	var c Credentials
	maps.Copy(fields, c.fields())
	if err := assignOnce(r.PostForm, fields); err != nil {
		return Credentials{}, err
	}
	authorizations := r.Header.Values("Authorization")
	switch {
	case len(authorizations) > 1:
		return Credentials{}, &Error{invalidRequest, "repeated Authorization header"}
	case len(authorizations) == 0 || authorizations[0] == "":
		return c, nil
	}
	scheme, credentials, _ := strings.Cut(authorizations[0], " ")
	if !strings.EqualFold(scheme, "Basic") {
		c.AuthScheme = scheme
		return c, nil
	}
	id, secret, ok := parseBasic(strings.TrimLeft(credentials, " "))
	if !ok {
		return Credentials{}, &Error{invalidClient, "malformed Basic credentials"}
	}
	c.AuthScheme, c.BasicID, c.BasicSecret = "Basic", id, secret
	return c, nil
}

// parseBasic decodes the form-encoded Client identifier and secret of Basic credentials.
func parseBasic(credentials string) (id, secret string, ok bool) {
	decoded, err := base64.StdEncoding.DecodeString(credentials)
	if err != nil {
		return "", "", false
	}
	encodedID, encodedSecret, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", false
	}
	id, err = url.QueryUnescape(encodedID)
	if err != nil {
		return "", "", false
	}
	secret, err = url.QueryUnescape(encodedSecret)
	return id, secret, err == nil
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
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// WriteToken writes a successful token response.
func WriteToken(w http.ResponseWriter, resp TokenResponse) {
	writeJSON(w, http.StatusOK, resp)
}

// WriteError writes a token or revocation endpoint error, as a 401 with challenge for invalid_client when challenge is set.
func WriteError(w http.ResponseWriter, e *Error, challenge string) {
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
