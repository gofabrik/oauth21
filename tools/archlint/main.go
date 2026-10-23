// Command archlint checks the architecture rules of a module: its non-test
// packages import only the standard library, and its layers do not depend,
// even indirectly, on the packages they may not use.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
)

// layers lists each layer with the standard and module packages it may not
// depend on, the latter relative to the module path. No layer may depend on
// the root package.
var layers = []struct {
	path   string
	std    []string
	denied []string
}{
	{"internal/protocol", []string{"net/http"}, []string{"internal/wire", "store", "memstore", "storetest"}},
	{"internal/wire", nil, []string{"store", "memstore", "storetest"}},
}

type pkg struct {
	ImportPath string
	Standard   bool
	Deps       []string
	Module     *struct {
		Path string
		Main bool
	}
}

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	os.Exit(run(dir, os.Stderr))
}

// run checks the module in dir, reports problems to stderr and returns the exit status.
func run(dir string, stderr io.Writer) int {
	pkgs, err := list(dir, stderr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "archlint:", err)
		return 2
	}
	problems := check(pkgs)
	for _, p := range problems {
		_, _ = fmt.Fprintln(stderr, "archlint:", p)
	}
	if len(problems) > 0 {
		return 1
	}
	return 0
}

func check(pkgs []pkg) []string {
	var problems []string
	for _, p := range pkgs {
		if p.Standard {
			continue
		}
		if p.Module == nil || !p.Module.Main {
			problems = append(problems, "non-stdlib import "+p.ImportPath)
			continue
		}
		module := p.Module.Path
		for _, l := range layers {
			if !within(p.ImportPath, module+"/"+l.path) {
				continue
			}
			for _, dep := range p.Deps {
				std := slices.ContainsFunc(l.std, func(d string) bool { return within(dep, d) })
				denied := slices.ContainsFunc(l.denied, func(d string) bool { return within(dep, module+"/"+d) })
				if dep == module || std || denied {
					problems = append(problems, p.ImportPath+" depends on "+dep)
				}
			}
		}
	}
	return problems
}

func within(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

func list(dir string, stderr io.Writer) ([]pkg, error) {
	cmd := exec.CommandContext(context.Background(), "go", "list", "-deps", "-json=ImportPath,Standard,Deps,Module", "./...")
	cmd.Dir = dir
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var pkgs []pkg
	dec := json.NewDecoder(out)
	for {
		var p pkg
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, cmd.Wait()
}
