package conformance

import (
	"net/url"
	"testing"
)

// newNamespaceServer starts an Authorization Server where the Resource Server Client may introspect and a service Client has the identifier alice, the subject of a Resource Owner.
func newNamespaceServer(t *testing.T) *authorizationServer {
	t.Helper()
	alice := serviceClient(t)
	alice.ID = "alice"
	return newAuthorizationServer(t, append(newIntrospectionClients(t), alice)...)
}

// aliceClientToken returns an access token the Client alice gets for itself with client credentials and params.
func (a *authorizationServer) aliceClientToken(params url.Values) string {
	a.t.Helper()
	access, _ := a.tokens(params, basic("alice", secret))
	return access
}

// subjectParams returns a client credentials request that also names the subject bob.
func subjectParams() url.Values {
	params := clientCredentialsParams("")
	for _, name := range []string{"sub", "subject", "username", "resource_owner"} {
		params.Set(name, "bob")
	}
	return params
}

// resourceOwnerToken returns an access token of the public Client that the Resource Owner alice authorized.
func (a *authorizationServer) resourceOwnerToken() string {
	a.t.Helper()
	access, _ := a.tokens(tokenParams(a.code(authorizeParams())), nil)
	return access
}

// TestClientCannotChooseSubject checks that subject parameters in a client credentials request do not give its access token a subject.
//
//conformance:covers OAUTH21D16-7.4-03
func TestClientCannotChooseSubject(t *testing.T) {
	a := newNamespaceServer(t)
	body := a.introspect(a.aliceClientToken(subjectParams()))
	if _, ok := body["sub"]; ok || body["active"] != true {
		t.Fatalf("got %v, want an active token without sub", body)
	}
}

// TestClientCannotChooseAudience checks that audience parameters in a client credentials request do not give its access token an audience.
//
//conformance:covers RFC9700-4.15.1-03
func TestClientCannotChooseAudience(t *testing.T) {
	a := newNamespaceServer(t)
	params := clientCredentialsParams("")
	for _, name := range []string{"resource", "audience", "aud"} {
		params.Set(name, "https://other.example")
	}
	body := a.introspect(a.aliceClientToken(params))
	if _, ok := body["aud"]; ok || body["active"] != true {
		t.Fatalf("got %v, want an active token without aud", body)
	}
}

// TestLocalValidationIgnoresChosenSubject checks that local validation of an access token requested with subject parameters gives no subject.
//
//conformance:covers RFC9700-2.6-10
func TestLocalValidationIgnoresChosenSubject(t *testing.T) {
	a := newNamespaceServer(t)
	token, err := a.local().Validate(t.Context(), a.aliceClientToken(subjectParams()))
	if err != nil || token.Subject != "" || token.ClientID != "alice" {
		t.Fatalf("got %+v and error %v, want a token of the Client alice without subject", token, err)
	}
}

// TestIntrospectionDistinguishesClientTokens checks that a Resource Server tells a Client's own access token from one the Resource Owner alice authorized by sub.
//
//conformance:covers OAUTH21D16-7.4-02
func TestIntrospectionDistinguishesClientTokens(t *testing.T) {
	a := newNamespaceServer(t)
	if body := a.introspect(a.resourceOwnerToken()); body["sub"] != "alice" {
		t.Fatalf("got %v for the Resource Owner's token, want sub alice", body)
	}
	if body := a.introspect(a.aliceClientToken(clientCredentialsParams(""))); body["sub"] != nil {
		t.Fatalf("got %v for the Client's own token, want no sub", body)
	}
}

// TestLocalValidationDistinguishesClientTokens checks that local validation tells a Client's own access token from one the Resource Owner alice authorized by Subject.
//
//conformance:covers RFC9700-4.15.1-02
func TestLocalValidationDistinguishesClientTokens(t *testing.T) {
	a := newNamespaceServer(t)
	v := a.local()
	if token, err := v.Validate(t.Context(), a.resourceOwnerToken()); err != nil || token.Subject != "alice" {
		t.Fatalf("got %+v and error %v for the Resource Owner's token, want subject alice", token, err)
	}
	if token, err := v.Validate(t.Context(), a.aliceClientToken(clientCredentialsParams(""))); err != nil || token.Subject != "" {
		t.Fatalf("got %+v and error %v for the Client's own token, want no subject", token, err)
	}
}
