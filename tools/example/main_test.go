package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// fake is the source of a fake demo program, which the FAIL and READY environment variables control.
const fake = `package main

import (
	"flag"
	"os"
	"os/signal"
	"path/filepath"
)

func main() {
	certOut := flag.String("cert-out", "", "")
	flag.String("ca", "", "")
	flag.Parse()
	switch os.Getenv("FAIL") {
	case %[1]q:
		os.Exit(1)
	case "hang":
		select {}
	}
	if *certOut != "" {
		_ = os.WriteFile(*certOut, []byte("certificate"), 0o600)
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	_ = os.WriteFile(filepath.Join(os.Getenv("READY"), %[1]q), nil, 0o600)
	<-interrupt
}
`

// examples writes an examples module whose demo programs are fakes to a temporary directory.
func examples(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{"go.mod": "module example.com/examples\n\ngo 1.26\n"}
	for _, name := range programs {
		files[filepath.Join("demo", name, "main.go")] = fmt.Sprintf(fake, name)
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("READY", t.TempDir())
	return dir
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestRunFailsWhenServerExits(t *testing.T) {
	dir := examples(t)
	t.Setenv("FAIL", "server")
	var out output
	if code := run(t.Context(), dir, time.Minute, &out, &out); code != 1 || !strings.Contains(out.String(), "server exited") {
		t.Fatalf("got exit status %d and output %q, want 1 saying the server exited", code, out.String())
	}
}

func TestRunFailsWhenServerIsNotReady(t *testing.T) {
	dir := examples(t)
	t.Setenv("FAIL", "hang")
	var out output
	if code := run(t.Context(), dir, 100*time.Millisecond, &out, &out); code != 1 || !strings.Contains(out.String(), "certificate") {
		t.Fatalf("got exit status %d and output %q, want 1 about the certificate", code, out.String())
	}
}

func TestRunFailsWhenClientExits(t *testing.T) {
	dir := examples(t)
	t.Setenv("FAIL", "client")
	var out output
	if code := run(t.Context(), dir, time.Minute, &out, &out); code != 1 || !strings.Contains(out.String(), "client") {
		t.Fatalf("got exit status %d and output %q, want 1 naming the client", code, out.String())
	}
}

func TestRunStopsOnInterrupt(t *testing.T) {
	dir := examples(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		for _, name := range programs {
			for !exists(filepath.Join(os.Getenv("READY"), name)) && ctx.Err() == nil {
				time.Sleep(10 * time.Millisecond)
			}
		}
		cancel()
	}()
	var out output
	if code := run(ctx, dir, time.Minute, &out, &out); code != 0 || strings.Contains(out.String(), "example:") {
		t.Fatalf("got exit status %d and output %q, want 0 and no error", code, out.String())
	}
}

func TestRunStopsOnInterruptDuringBuild(t *testing.T) {
	dir := examples(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out output
	if code := run(ctx, dir, time.Minute, &out, &out); code != 0 || strings.Contains(out.String(), "example:") {
		t.Fatalf("got exit status %d and output %q, want 0 and no error", code, out.String())
	}
}

func TestRunFailsWhenBuildFails(t *testing.T) {
	dir := examples(t)
	if err := os.WriteFile(filepath.Join(dir, "demo", "client", "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out output
	if code := run(t.Context(), dir, time.Minute, &out, &out); code != 1 || !strings.Contains(out.String(), "example: build:") {
		t.Fatalf("got exit status %d and output %q, want 1 reporting the build", code, out.String())
	}
}

func exists(name string) bool {
	_, err := os.Stat(name) // #nosec G703 -- name is in the test's temporary directory
	return err == nil
}

// output collects what the programs write from several goroutines.
type output struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}
