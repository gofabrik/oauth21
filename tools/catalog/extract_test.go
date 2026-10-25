package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const spec = "\xef\xbb\xbf" + `
Internet Engineering Task Force (IETF)                      A. Author
Request for Comments: 9999                                 March 2020

Abstract

   Clients MUST NOT be counted before the first section.

1.  Introduction

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in
   [RFC2119].

   A client must be careful.  A server may refuse it.

4.1.  Requests

   code_challenge
      REQUIRED.  Code challenge.

   The server MUST NOT accept a request without it, e.g., a request
   from a public client.  It SHOULD log the attempt and MAY close the
   connection.  It is NOT RECOMMENDED to retry.

   Values ending with a period character (.)
   SHOULD be rejected.

   A server MUST reject an expired
   inter-
   operable request.

   A server that receives a token request with an expired code then MUST



Author                     Standards Track                    [Page 1]
` + "\f" + `
RFC 9999                         Example                     March 2020


   NOT accept it.

   GET /authorize?client_id=s6BhdRkqt3



Author                     Standards Track                    [Page 2]
` + "\f" + `
RFC 9999                         Example                     March 2020


   Servers MAY cache it.

5.  Lists

   The authorization server MUST:

   o  authenticate the client, and

   o  validate the code.

   Clients MUST register:

   o  Public clients.

   o  Native clients.

   Clients MAY retry.

   o  Native clients SHOULD use PKCE.

Appendix A.  Notes

   Implementers SHOULD read this.

Appendix B.  Document History

   Changed SHOULD to MUST.
`

const header = `document: RFC9999
title: Example
source: rfc9999.txt
`

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runExtract(t *testing.T, dir string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run([]string{"extract", filepath.Join(dir, "rfc9999.yaml")}, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(dir), name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestExtractCandidates(t *testing.T) {
	dir := writeFiles(t, map[string]string{"rfc9999.txt": spec, "rfc9999.yaml": header})
	runExtract(t, dir)

	want := header + `requirements:
  - id: RFC9999-4.1-01
    section: "4.1"
    keyword: REQUIRED
    text: code_challenge REQUIRED.
    status: ""
  - id: RFC9999-4.1-02
    section: "4.1"
    keyword: MUST NOT
    text: The server MUST NOT accept a request without it, e.g., a request from a public client.
    status: ""
  - id: RFC9999-4.1-03
    section: "4.1"
    keyword: SHOULD
    text: It SHOULD log the attempt and MAY close the connection.
    status: ""
  - id: RFC9999-4.1-04
    section: "4.1"
    keyword: MAY
    text: It SHOULD log the attempt and MAY close the connection.
    status: ""
  - id: RFC9999-4.1-05
    section: "4.1"
    keyword: NOT RECOMMENDED
    text: It is NOT RECOMMENDED to retry.
    status: ""
  - id: RFC9999-4.1-06
    section: "4.1"
    keyword: SHOULD
    text: Values ending with a period character (.) SHOULD be rejected.
    status: ""
  - id: RFC9999-4.1-07
    section: "4.1"
    keyword: MUST
    text: A server MUST reject an expired inter-operable request.
    status: ""
  - id: RFC9999-4.1-08
    section: "4.1"
    keyword: MUST NOT
    text: A server that receives a token request with an expired code then MUST NOT accept it.
    status: ""
  - id: RFC9999-4.1-09
    section: "4.1"
    keyword: MAY
    text: Servers MAY cache it.
    status: ""
  - id: RFC9999-5-01
    section: "5"
    keyword: MUST
    text: 'The authorization server MUST: authenticate the client, and validate the code.'
    status: ""
  - id: RFC9999-5-02
    section: "5"
    keyword: MUST
    text: 'Clients MUST register: Public clients. Native clients.'
    status: ""
  - id: RFC9999-5-03
    section: "5"
    keyword: MAY
    text: Clients MAY retry.
    status: ""
  - id: RFC9999-5-04
    section: "5"
    keyword: SHOULD
    text: Native clients SHOULD use PKCE.
    status: ""
  - id: RFC9999-A-01
    section: A
    keyword: SHOULD
    text: Implementers SHOULD read this.
    status: ""
`
	if got := readFile(t, dir, "rfc9999.yaml"); got != want {
		t.Errorf("catalog:\n%s\nwant:\n%s", got, want)
	}

	if out := runExtract(t, dir); out != "" {
		t.Errorf("second run reported:\n%s", out)
	}
	if got := readFile(t, dir, "rfc9999.yaml"); got != want {
		t.Errorf("second run changed the catalog:\n%s", got)
	}
}

const curated = header + `# Curated by hand.
requirements:
  - id: RFC9999-4.1-01
    section: "4.1"
    keyword: REQUIRED
    text: code_challenge REQUIRED.
    statement: code_challenge is REQUIRED in the authorization request.
    status: applicable
  - id: RFC9999-4.1-02
    section: "4.1"
    keyword: MUST NOT
    text: The server MUST NOT accept a request without it, e.g., a request from a public client.
    status: superseded
    superseded_by: [RFC9999-4.1-03]
  - id: RFC9999-4.1-03
    section: "4.1"
    keyword: SHOULD
    text: It SHOULD log the attempt and MAY drop the connection.
    statement: It SHOULD log the attempt.
    status: applicable
    note: Logging is left to the Host Application.
  - id: RFC9999-4.1-07
    section: "4.1"
    keyword: MAY
    text: It SHOULD log the attempt and MAY drop the connection.
    statement: It MAY drop the connection.
    status: out-of-scope
    reason: client-requirement
  - id: RFC9999-4.1-05
    section: "4.1"
    keyword: MUST
    text: A server MUST reject an expired request.
    status: applicable
  - id: RFC9999-4.1-06
    section: "4.1"
    keyword: MUST
    text: Servers MUST answer quickly.
    status: applicable
  - id: RFC9999-A-01
    section: A
    keyword: MAY
    text: Implementers MAY read this.
    status: informative
`

func TestExtractKeepsCuration(t *testing.T) {
	dir := writeFiles(t, map[string]string{"rfc9999.txt": spec, "rfc9999.yaml": curated})
	out := runExtract(t, dir)

	wantOut := `changed RFC9999-4.1-03, RFC9999-4.1-07: It SHOULD log the attempt and MAY close the connection.
new RFC9999-4.1-04: It is NOT RECOMMENDED to retry.
new RFC9999-4.1-08: Values ending with a period character (.) SHOULD be rejected.
changed RFC9999-4.1-05: A server MUST reject an expired inter-operable request.
new RFC9999-4.1-09: A server that receives a token request with an expired code then MUST NOT accept it.
new RFC9999-4.1-10: Servers MAY cache it.
new RFC9999-5-01: The authorization server MUST: authenticate the client, and validate the code.
new RFC9999-5-02: Clients MUST register: Public clients. Native clients.
new RFC9999-5-03: Clients MAY retry.
new RFC9999-5-04: Native clients SHOULD use PKCE.
changed RFC9999-A-01: Implementers SHOULD read this.
removed RFC9999-4.1-06: Servers MUST answer quickly.
`
	if out != wantOut {
		t.Errorf("report:\n%s\nwant:\n%s", out, wantOut)
	}

	got := readFile(t, dir, "rfc9999.yaml")
	if !strings.HasPrefix(got, curated) {
		t.Errorf("curated requirements changed:\n%s", got)
	}
	if !strings.HasSuffix(got, `  - id: RFC9999-5-04
    section: "5"
    keyword: SHOULD
    text: Native clients SHOULD use PKCE.
    status: ""
`) {
		t.Errorf("new requirements not appended:\n%s", got)
	}
}

func TestExtractHangingIndentAcrossPages(t *testing.T) {
	text, err := os.ReadFile("../../conformance/specs/draft-ietf-oauth-v2-1-16.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := Candidate{
		Section: "5.3.1",
		Keyword: May,
		Text:    `"error_description": The resource server MAY include the error_description attribute to provide developers a human-readable explanation that is not meant to be displayed to end users.`,
	}
	if !slices.Contains(Extract(string(text)), want) {
		t.Errorf("no candidate %q", want.Text)
	}
}

func TestExtractRefusesToRewrite(t *testing.T) {
	dir := writeFiles(t, map[string]string{"rfc9999.txt": spec, "rfc9999.yaml": header + "requirements: []\n"})
	err := run([]string{"extract", filepath.Join(dir, "rfc9999.yaml")}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "cannot append") {
		t.Fatalf("got error %v, want cannot append", err)
	}
	if got := readFile(t, dir, "rfc9999.yaml"); got != header+"requirements: []\n" {
		t.Errorf("catalog changed:\n%s", got)
	}
}

func TestRunUsage(t *testing.T) {
	err := run([]string{"extract"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("got error %v, want usage", err)
	}
}

func FuzzExtract(f *testing.F) {
	f.Add(spec)
	f.Add("1.  A\n\n   x MUST\n\fRFC 1  y\n   z.  \"MAY\" MAY.")
	f.Fuzz(func(t *testing.T, text string) {
		for _, s := range Extract(text) {
			if !sectionID.MatchString(s.Section) {
				t.Errorf("invalid section %q", s.Section)
			}
			if !strings.Contains(s.Text, string(s.Keyword)) {
				t.Errorf("%q does not contain %q", s.Text, s.Keyword)
			}
			if s.Text != strings.Join(strings.Fields(s.Text), " ") {
				t.Errorf("%q is not normalized", s.Text)
			}
		}
	})
}
