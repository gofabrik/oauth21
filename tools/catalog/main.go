// Command catalog manages the requirement catalog.
package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "catalog:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 2 || args[0] != "validate" {
		return errors.New("usage: catalog validate DIR")
	}
	_, err := Load(os.DirFS(args[1]))
	return err
}
