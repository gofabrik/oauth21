package wire

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	invalidRequest    = "invalid_request"
	invalidClient     = "invalid_client"
	insufficientScope = "insufficient_scope"
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
	return parseTokenParam(r)
}

// ParseIntrospectionRequest reads the token of an introspection request from the form body of a POST, ignoring the value of token_type_hint, and the Client credentials of its Authorization header.
func ParseIntrospectionRequest(r *http.Request) (string, Credentials, *Error) {
	return parseTokenParam(r)
}

// parseTokenParam reads token and token_type_hint from the form body of a POST and returns the token and the Client credentials.
func parseTokenParam(r *http.Request) (string, Credentials, *Error) {
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
	writeNoStoreJSON(w, http.StatusOK, resp)
}

// IntrospectionResponse is an introspection response; for an inactive token it is the zero value, which encodes as active false only.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	Audience  audience `json:"aud,omitempty"`
}

// WriteIntrospection writes an introspection response.
func WriteIntrospection(w http.ResponseWriter, resp IntrospectionResponse) {
	writeNoStoreJSON(w, http.StatusOK, resp)
}

// WriteIntrospectionError writes an introspection endpoint error, as a 401 with a Basic challenge for invalid_client.
func WriteIntrospectionError(w http.ResponseWriter, e *Error) {
	WriteError(w, e, "Basic")
}

// maxIntrospectionResponseSize is the largest response body ParseIntrospectionResponse reads.
const maxIntrospectionResponseSize = 1 << 20

// NewIntrospectionRequest returns an introspection request for token to endpoint, authenticated with client_secret_basic.
func NewIntrospectionRequest(ctx context.Context, endpoint, token, clientID, clientSecret string) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(clientID)+":"+url.QueryEscape(clientSecret))))
	return r, nil
}

// ParseIntrospectionResponse reads a successful introspection response, leaving ExpiresAt zero, as the zero value for an inactive token, and fails for any other response.
func ParseIntrospectionResponse(resp *http.Response) (IntrospectionResponse, error) {
	if resp.StatusCode != http.StatusOK {
		return IntrospectionResponse{}, fmt.Errorf("introspection failed with status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxIntrospectionResponseSize+1))
	if err != nil {
		return IntrospectionResponse{}, err
	}
	if len(raw) > maxIntrospectionResponseSize {
		return IntrospectionResponse{}, errors.New("introspection response too large")
	}
	members, err := objectMembers(raw)
	if err != nil {
		return IntrospectionResponse{}, fmt.Errorf("malformed introspection response: %w", err)
	}
	active, ok := members["active"]
	if !ok || string(active) == "null" {
		return IntrospectionResponse{}, errors.New("malformed introspection response: no active")
	}
	var ir IntrospectionResponse
	if err := json.Unmarshal(active, &ir.Active); err != nil {
		return IntrospectionResponse{}, fmt.Errorf("malformed introspection response: %w", err)
	}
	if !ir.Active {
		return IntrospectionResponse{}, nil
	}
	fields := map[string]any{"scope": &ir.Scope, "client_id": &ir.ClientID, "sub": &ir.Subject, "aud": &ir.Audience}
	for name, field := range fields {
		if m, ok := members[name]; ok {
			if err := json.Unmarshal(m, field); err != nil {
				return IntrospectionResponse{}, fmt.Errorf("malformed introspection response: %w", err)
			}
		}
	}
	return ir, nil
}

// objectMembers returns the members of the JSON object raw, and fails for anything else, including a repeated member name.
func objectMembers(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	members := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name := t.(string)
		if _, ok := members[name]; ok {
			return nil, fmt.Errorf("repeated member %q", name)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		members[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the JSON object")
	}
	return members, nil
}

// audience is an aud value, which is a string or an array of strings (RFC 7519 4.1.3).
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var many []string
	if json.Unmarshal(data, &many) == nil {
		if len(many) == 0 {
			many = nil
		}
		*a = many
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*a = audience{one}
	return nil
}

// Metadata is an authorization server metadata document (RFC 8414 2).
type Metadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                              string   `json:"token_endpoint,omitempty"`
	RevocationEndpoint                         string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                        []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthMethodsSupported  []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported,omitempty"`
}

// WriteMetadata writes the metadata document m, which Clients may cache, in answer to a GET or HEAD, and 405 otherwise.
func WriteMetadata(w http.ResponseWriter, r *http.Request, m Metadata) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	encodeJSON(w, http.StatusOK, m)
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
	writeNoStoreJSON(w, status, struct {
		Error       string `json:"error"`
		Description string `json:"error_description,omitempty"`
	}{e.Code, e.Description})
}

func writeNoStoreJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	encodeJSON(w, status, v)
}

func encodeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ParseBearer reads the access token of the Bearer credentials in the Authorization header of r, "" without them; it ignores access tokens in the query and the body.
func ParseBearer(r *http.Request) (string, *Error) {
	authorizations := r.Header.Values("Authorization")
	switch {
	case len(authorizations) > 1:
		return "", &Error{invalidRequest, "repeated Authorization header"}
	case len(authorizations) == 0:
		return "", nil
	}
	scheme, credentials, _ := strings.Cut(authorizations[0], " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", nil
	}
	token := strings.TrimLeft(credentials, " ")
	if !token68(token) {
		return "", &Error{invalidRequest, "malformed Bearer credentials"}
	}
	return token, nil
}

// token68 reports whether v is a token68 (RFC 9110).
func token68(v string) bool {
	trimmed := strings.TrimRight(v, "=")
	return trimmed != "" && strings.IndexFunc(trimmed, func(c rune) bool { return !token68Char(c) }) < 0
}

// token68Char reports whether c may appear in a token68 before its trailing '=' characters.
func token68Char(c rune) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.ContainsRune("-._~+/", c)
}

// WriteBearerError writes a Bearer challenge for e, without error when e is nil, naming the required scope when it is set.
func WriteBearerError(w http.ResponseWriter, e *Error, scope string) {
	if e != nil && e.Code == ServerError {
		w.WriteHeader(e.Status())
		return
	}
	status, challenge := http.StatusUnauthorized, `Bearer realm="oauth21"`
	if scope != "" {
		challenge += `, scope="` + scope + `"`
	}
	if e != nil {
		switch e.Code {
		case invalidRequest:
			status = e.Status()
		case insufficientScope:
			status = http.StatusForbidden
		}
		challenge += `, error="` + e.Code + `"`
		if e.Description != "" {
			challenge += `, error_description="` + e.Description + `"`
		}
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.WriteHeader(status)
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
