package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/gofabrik/oauth21/bearer"
)

// newResourceServer returns a Resource Server that serves /hello to access tokens that v validates and that have the scope.
func newResourceServer(v bearer.Validator) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /hello", bearer.SecureMiddleware(loopback, v, scope)(http.HandlerFunc(hello)))
	return mux
}

// loopback declares requests from a loopback address secure, for development only.
func loopback(r *http.Request) bool {
	addr, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && addr.Addr().IsLoopback()
}

func hello(w http.ResponseWriter, r *http.Request) {
	t, _ := bearer.FromContext(r.Context())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, "Hello, %s. Scopes: %s.\n", t.Subject, strings.Join(t.Scopes, " "))
}
