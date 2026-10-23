// Command catalog manages the requirement catalog.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var errUsage = errors.New("usage: catalog validate DIR | catalog extract FILE.yaml | catalog coverage REPO [BASE]")

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "catalog:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 3 && args[0] == "coverage" {
		return coverRepo(args[1], args[2], stdout) // #nosec G602 -- len(args) is 3
	}
	if len(args) != 2 {
		return errUsage
	}
	switch args[0] {
	case "validate":
		_, err := Load(os.DirFS(args[1]))
		return err
	case "extract":
		return extractFile(args[1], stdout)
	case "coverage":
		return coverRepo(args[1], "", stdout)
	}
	return errUsage
}
