// Command archlint checks the architecture rules of a module: its non-test
// packages import only the standard library.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type pkg struct {
	ImportPath string
	Standard   bool
	Module     *struct{ Main bool }
}

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	deps, err := external(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(deps) > 0 {
		fmt.Fprintf(os.Stderr, "non-stdlib imports:\n  %s\n", strings.Join(deps, "\n  "))
		os.Exit(1)
	}
}

func external(dir string) ([]string, error) {
	cmd := exec.CommandContext(context.Background(), "go", "list", "-deps", "-json=ImportPath,Standard,Module", "./...")
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var deps []string
	dec := json.NewDecoder(out)
	for {
		var p pkg
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		if !p.Standard && (p.Module == nil || !p.Module.Main) {
			deps = append(deps, p.ImportPath)
		}
	}
	return deps, cmd.Wait()
}
