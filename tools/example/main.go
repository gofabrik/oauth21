// Command example builds the demo programs of the examples module and runs them until one of them exits or it is interrupted.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// programs are the demo programs in the order they start, the Authorization Server first.
var programs = []string{"server", "resourceserver", "client"}

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, dir, 30*time.Second, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run builds and runs the demo programs of the examples module in dir until ctx is done, waiting at most readyTimeout for the Authorization Server, and returns the exit status.
func run(ctx context.Context, dir string, readyTimeout time.Duration, stdout, stderr io.Writer) int {
	bin, err := os.MkdirTemp("", "oauth21-example-")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "example:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(bin) }()
	args := []string{"build", "-o", bin + string(filepath.Separator)}
	for _, name := range programs {
		args = append(args, "./demo/"+name)
	}
	build := exec.CommandContext(ctx, "go", args...) // #nosec G204 -- bin is a temporary directory of run
	build.Dir, build.Stdout, build.Stderr = dir, stdout, stderr
	if err := build.Run(); err != nil {
		if ctx.Err() != nil {
			return 0
		}
		_, _ = fmt.Fprintln(stderr, "example: build:", err)
		return 1
	}

	interrupt, stop := context.WithCancel(context.WithoutCancel(ctx))
	l := &launcher{interrupt: interrupt, readyTimeout: readyTimeout, bin: bin, stdout: stdout, stderr: stderr, exits: make(chan exit, len(programs))}
	err = l.supervise(ctx)
	stop()
	l.running.Wait()
	if err != nil && ctx.Err() == nil {
		_, _ = fmt.Fprintln(stderr, "example:", err)
		return 1
	}
	return 0
}

// launcher runs the built demo programs until its interrupt context is done.
type launcher struct {
	interrupt      context.Context
	readyTimeout   time.Duration
	bin            string
	stdout, stderr io.Writer
	exits          chan exit
	running        sync.WaitGroup
}

type exit struct {
	name string
	err  error
}

// supervise runs the programs until ctx is done or one of them exits.
func (l *launcher) supervise(ctx context.Context) error {
	ca := filepath.Join(l.bin, "demo-ca.pem")
	if err := l.start(programs[0], "-cert-out", ca); err != nil {
		return err
	}
	if err := l.awaitCertificate(ctx, ca); err != nil {
		return err
	}
	for _, name := range programs[1:] {
		if err := l.start(name, "-ca", ca); err != nil {
			return err
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case e := <-l.exits:
		if e.err != nil {
			return fmt.Errorf("%s: %w", e.name, e.err)
		}
		return nil
	}
}

// awaitCertificate waits at most l.readyTimeout for the certificate file ca of the Authorization Server.
func (l *launcher) awaitCertificate(ctx context.Context, ca string) error {
	timeout := time.NewTimer(l.readyTimeout)
	defer timeout.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(ca); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-l.exits:
			return errors.Join(fmt.Errorf("%s exited before writing its certificate", e.name), e.err)
		case <-timeout.C:
			return fmt.Errorf("server did not write its certificate within %v", l.readyTimeout)
		case <-tick.C:
		}
	}
}

// start starts the program name with args, which is interrupted when l.interrupt is done.
func (l *launcher) start(name string, args ...string) error {
	cmd := exec.CommandContext(l.interrupt, filepath.Join(l.bin, name), args...) // #nosec G204 -- the programs are built by run
	cmd.Stdout, cmd.Stderr = l.stdout, l.stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Start(); err != nil {
		return err
	}
	l.running.Go(func() { l.exits <- exit{name, cmd.Wait()} })
	return nil
}
