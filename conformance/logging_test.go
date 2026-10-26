package conformance

import (
	"bytes"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// logBuffer is the output of the default loggers while a test runs.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogs sends the output of the log/slog default logger, and with it of the log default logger, to the returned buffer until t ends.
func captureLogs(t *testing.T) *logBuffer {
	t.Helper()
	logger, output, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(output)
		log.SetFlags(flags)
	})
	b := &logBuffer{}
	slog.SetDefault(slog.New(slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return b
}

// TestLogsCarryNoSecrets checks that codes, access tokens, refresh tokens, Client secrets and code verifiers reach neither the log nor the log/slog default logger, at every endpoint, with either way of sending a Client secret and also in failed requests.
//
//conformance:covers INV-0007
func TestLogsCarryNoSecrets(t *testing.T) {
	const wrongSecret, wrongVerifier = "wr0ng-s3cret", "wr0ng-v3rifier-wr0ng-v3rifier-wr0ng-v3rifier"
	a := newFlowServer(t)
	logs := captureLogs(t)
	unknown := authorizeParams()
	unknown.Set("client_id", "unknown")
	a.send(http.MethodGet, "/authorize?"+unknown.Encode(), "", nil)
	a.deny(a.pending(a.authorize(authorizeParams())).ID)
	params := authorizeParams()
	params.Set("client_id", confidentialID)
	code := a.code(params)
	redemption := tokenParams(code)
	redemption.Del("client_id")
	a.token(redemption, basic(confidentialID, wrongSecret))
	a.token(withVerifier(redemption, wrongVerifier), basic(confidentialID, secret))
	access, refresh := a.tokens(redemption, basic(confidentialID, secret))
	posted := confidentialRefreshParams(refresh)
	posted.Set("client_id", confidentialID)
	posted.Set("client_secret", secret)
	refreshed, rotated := a.tokens(posted, nil)
	a.introspect(refreshed)
	a.token(confidentialRefreshParams(rotated), basic(confidentialID, wrongSecret))
	a.token(confidentialRefreshParams(refresh), basic(confidentialID, secret))
	a.token(redemption, basic(confidentialID, secret))
	live, revoked := a.tokens(a.confidentialCode(), basic(confidentialID, secret))
	a.revoke(url.Values{"token": {live}}, basic(confidentialID, secret))
	a.revoke(url.Values{"token": {revoked}, "client_id": {confidentialID}, "client_secret": {secret}}, nil)
	a.send(http.MethodPost, "/revoke", url.Values{"token": {revoked}}.Encode(), basic(confidentialID, wrongSecret))
	service, _ := a.tokens(clientCredentialsParams(""), basic(serviceID, secret))
	a.send(http.MethodPost, "/introspect", url.Values{"token": {service}}.Encode(), basic(resourceServerID, wrongSecret))
	secrets := []string{code, access, refresh, refreshed, rotated, live, revoked, service, secret, url.QueryEscape(secret), wrongSecret, verifier, wrongVerifier}
	for _, h := range []http.Header{basic(confidentialID, secret), basic(confidentialID, wrongSecret), basic(serviceID, secret), basic(resourceServerID, secret), basic(resourceServerID, wrongSecret)} {
		secrets = append(secrets, strings.TrimPrefix(h.Get("Authorization"), "Basic "))
	}
	out := logs.String()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Fatalf("got logs %q, want none of %q", out, s)
		}
	}
}
