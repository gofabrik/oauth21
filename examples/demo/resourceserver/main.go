// Command resourceserver runs the demo Resource Server.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofabrik/oauth21/bearer"
)

const (
	clientID     = "demo-resource-server"
	clientSecret = "demo-resource-server-secret" // #nosec G101 -- the secret of the demo Resource Server
	scope        = "profile"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9002", "address to listen on")
	introspection := flag.String("introspection-endpoint", "https://127.0.0.1:9000/introspect", "URL of the introspection endpoint of the Authorization Server")
	ca := flag.String("ca", "demo-ca.pem", "file with the certificate of the Authorization Server")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *addr, *introspection, *ca); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, addr, introspection, ca string) error {
	httpClient, err := trusting(ca)
	if err != nil {
		return err
	}
	defer httpClient.CloseIdleConnections()
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("Resource Server at %s/hello.", loopbackURL("http", ln.Addr()))
	v := bearer.Remote{Endpoint: introspection, ClientID: clientID, ClientSecret: clientSecret, Client: httpClient}
	srv := &http.Server{Handler: newResourceServer(v), ReadHeaderTimeout: 10 * time.Second}
	return serve(ctx, srv, ln)
}

// trusting returns an HTTP client that trusts the certificates in the PEM file ca.
func trusting(ca string) (*http.Client, error) {
	data, err := os.ReadFile(ca) // #nosec G304 -- the file is given on the command line
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s: no certificate", ca)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}, Timeout: 10 * time.Second}, nil
}

// loopbackURL returns the URL with scheme of the listener address addr, naming 127.0.0.1 when addr is unspecified.
func loopbackURL(scheme string, addr net.Addr) string {
	a := addr.(*net.TCPAddr).AddrPort()
	if a.Addr().IsUnspecified() {
		a = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), a.Port())
	}
	return scheme + "://" + a.String()
}

// serve serves srv on ln until ctx is done.
func serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errs := make(chan error, 1)
	go func() { errs <- srv.Serve(ln) }()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
