package main

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func runList(t *testing.T, args ...string) string {
	t.Helper()
	dir := writeFiles(t, map[string]string{"rfc9999.yaml": curated + `  - id: RFC9999-4.1.2-01
    section: "4.1.2"
    keyword: MUST
    text: Clients MUST retry.
    status: ""
  - id: RFC9999-4.10-01
    section: "4.10"
    keyword: MAY
    text: Servers MAY wait.
    status: ""
  - id: RFC9999-5-01
    section: "5"
    keyword: SHOULD
    text: Servers SHOULD accept plain.
    status: deviates
    note: spec.md accepts S256 only.
`})
	var out bytes.Buffer
	if err := run(append([]string{"list", filepath.Join(dir, "rfc9999.yaml")}, args...), &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestList(t *testing.T) {
	want := `RFC9999-4.1-01	REQUIRED	applicable	code_challenge is REQUIRED in the authorization request.
RFC9999-4.1-02	MUST NOT	superseded	The server MUST NOT accept a request without it, e.g., a request from a public client.
RFC9999-4.1-03	SHOULD	applicable	It SHOULD log the attempt.
RFC9999-4.1-07	MAY	out-of-scope	It MAY drop the connection.
RFC9999-4.1-05	MUST	applicable	A server MUST reject an expired request.
RFC9999-4.1-06	MUST	applicable	Servers MUST answer quickly.
RFC9999-A-01	MAY	informative	Implementers MAY read this.
RFC9999-4.1.2-01	MUST	-	Clients MUST retry.
RFC9999-4.10-01	MAY	-	Servers MAY wait.
RFC9999-5-01	SHOULD	deviates	Servers SHOULD accept plain.
`
	if got := runList(t); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestListFilters(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"status", []string{"--status", "out-of-scope"}, []string{"RFC9999-4.1-07"}},
		{"deviates", []string{"--status", "deviates"}, []string{"RFC9999-5-01"}},
		{"uncurated", []string{"--status", "-"}, []string{"RFC9999-4.1.2-01", "RFC9999-4.10-01"}},
		{"section and subsections", []string{"--section", "4.1"}, []string{"RFC9999-4.1-01", "RFC9999-4.1-02", "RFC9999-4.1-03", "RFC9999-4.1-07", "RFC9999-4.1-05", "RFC9999-4.1-06", "RFC9999-4.1.2-01"}},
		{"appendix", []string{"--section", "A"}, []string{"RFC9999-A-01"}},
		{"both", []string{"--section", "4.1", "--status", "-"}, []string{"RFC9999-4.1.2-01"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ids []string
			for _, line := range strings.Split(strings.TrimSuffix(runList(t, tc.args...), "\n"), "\n") {
				id, _, _ := strings.Cut(line, "\t")
				ids = append(ids, id)
			}
			if !slices.Equal(ids, tc.want) {
				t.Errorf("got %v, want %v", ids, tc.want)
			}
		})
	}
}

func TestListFlagsBeforeFile(t *testing.T) {
	dir := writeFiles(t, map[string]string{"rfc9999.yaml": curated})
	var out bytes.Buffer
	if err := run([]string{"list", "--status", "informative", filepath.Join(dir, "rfc9999.yaml")}, &out); err != nil {
		t.Fatal(err)
	}
	if want := "RFC9999-A-01\tMAY\tinformative\tImplementers MAY read this.\n"; out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}

func TestListInvalid(t *testing.T) {
	dir := writeFiles(t, map[string]string{"rfc9999.yaml": curated})
	file := filepath.Join(dir, "rfc9999.yaml")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no file", []string{"list"}, "usage"},
		{"unknown flag", []string{"list", file, "--keyword", "MUST"}, "usage"},
		{"extra argument", []string{"list", file, "other.yaml"}, "usage"},
		{"unknown status", []string{"list", file, "--status", "curated"}, `unknown status "curated"`},
		{"missing file", []string{"list", filepath.Join(dir, "missing.yaml")}, "no such file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(tc.args, &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got error %v, want %q", err, tc.want)
			}
			if out.Len() > 0 {
				t.Errorf("printed:\n%s", out.String())
			}
		})
	}
}
