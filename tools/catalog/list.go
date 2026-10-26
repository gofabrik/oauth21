package main

import (
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
)

// noStatus stands for a Requirement without a status.
const noStatus = "-"

// listFile prints one line per Requirement of a catalog file: ID, keyword, status and statement or text.
func listFile(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	status := flags.String("status", "", "")
	section := flags.String("section", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() == 0 {
		return errUsage
	}
	name := flags.Arg(0)
	if err := flags.Parse(flags.Args()[1:]); err != nil || flags.NArg() > 0 {
		return errUsage
	}
	if *status != "" && *status != noStatus && !slices.Contains(statuses, Status(*status)) {
		return fmt.Errorf("unknown status %q", *status)
	}

	_, d, err := readDocument(name)
	if err != nil {
		return err
	}
	for _, r := range d.Requirements {
		s, text := string(r.Status), r.Statement
		if s == "" {
			s = noStatus
		}
		if text == "" {
			text = r.Text
		}
		if *status != "" && s != *status {
			continue
		}
		if *section != "" && r.Section != *section && !strings.HasPrefix(r.Section, *section+".") {
			continue
		}
		if _, err := fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", r.ID, r.Keyword, s, text); err != nil {
			return err
		}
	}
	return nil
}
