// Command server runs the demo Authorization Server.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gofabrik/oauth21"
	"github.com/gofabrik/oauth21/store"
)

// redirectURIs are the Client's callback on any loopback port.
var redirectURIs = []string{"http://127.0.0.1/callback", "http://[::1]/callback"}

const (
	username = "demo"
	password = "demo"
	scope    = "profile"

	clientID             = "demo-client"
	resourceServerID     = "demo-resource-server"
	resourceServerSecret = "demo-resource-server-secret" // #nosec G101 -- the secret of the demo Resource Server
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "address to listen on")
	certOut := flag.String("cert-out", "demo-ca.pem", "file to write the self-signed certificate to")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *addr, *certOut); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, addr, certOut string) error {
	cert, err := selfSigned()
	if err != nil {
		return err
	}
	hash, err := oauth21.PBKDF2{}.Hash(resourceServerSecret)
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	issuer := loopbackURL("https", ln.Addr())
	as, err := newAuthorizationServer(issuer, []string{scope},
		store.Client{ID: clientID, Type: store.Public, RedirectURIs: redirectURIs, AllowedScopes: []string{scope}, DefaultScopes: []string{scope}},
		store.Client{ID: resourceServerID, Type: store.Confidential, SecretHash: hash, Introspect: true},
	)
	if err != nil {
		return errors.Join(err, ln.Close())
	}
	if err := writeCertificate(certOut, cert.Leaf); err != nil {
		return errors.Join(err, ln.Close())
	}
	log.Printf("Authorization Server at %s, its certificate is in %s.", issuer, certOut)
	srv := &http.Server{Handler: as, ReadHeaderTimeout: 10 * time.Second}
	return serve(ctx, srv, tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}))
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

// writeCertificate writes cert to the file name atomically.
func writeCertificate(name string, cert *x509.Certificate) error {
	f, err := os.CreateTemp(filepath.Dir(name), filepath.Base(name)+".*")
	if err != nil {
		return err
	}
	_, err = f.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	if err = errors.Join(err, f.Close()); err == nil {
		err = os.Rename(f.Name(), name)
	}
	if err != nil {
		return errors.Join(err, os.Remove(f.Name()))
	}
	return nil
}

// selfSigned returns a self-signed certificate for the loopback addresses.
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "oauth21 demo"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
