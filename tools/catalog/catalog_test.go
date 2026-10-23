package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

const rfc6749 = `
document: RFC6749
title: The OAuth 2.0 Authorization Framework
source: specs/rfc6749.txt
requirements:
  - id: RFC6749-4.1.2-01
    section: "4.1.2"
    keyword: MUST
    text: The authorization code MUST expire shortly after it is issued.
    status: applicable
  - id: RFC6749-4.2-01
    section: "4.2"
    keyword: MUST
    text: The authorization server MUST NOT issue a refresh token.
    status: superseded
    superseded_by: [OAUTH21D16-4.1-01]
`

const oauth21 = `
document: OAUTH21D16
title: The OAuth 2.1 Authorization Framework
source: specs/draft-ietf-oauth-v2-1-16.txt
requirements:
  - id: OAUTH21D16-4.1-01
    section: "4.1"
    keyword: MUST
    text: Clients MUST use code_challenge.
    status: applicable
`

const invariants = `
document: INV
title: Security Invariants
requirements:
  - id: INV-0001
    keyword: MUST
    text: An authorization code issues tokens at most once.
    status: applicable
`

func load(files map[string]string) error {
	fsys := fstest.MapFS{}
	for name, data := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(data)}
	}
	_, err := Load(fsys)
	return err
}

func TestLoadValid(t *testing.T) {
	fsys := fstest.MapFS{
		"rfc6749.yaml":    {Data: []byte(rfc6749)},
		"oauth21d16.yaml": {Data: []byte(oauth21)},
		"invariants.yaml": {Data: []byte(invariants)},
		"README.md":       {Data: []byte("ignored")},
	}
	c, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Documents) != 3 {
		t.Fatalf("got %d documents, want 3", len(c.Documents))
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name:  "second document",
			files: map[string]string{"a.yaml": invariants + "---\ndocument: bad\n"},
			want:  "a.yaml: more than one YAML document",
		},
		{
			name:  "empty file",
			files: map[string]string{"a.yaml": ""},
			want:  "a.yaml: empty file",
		},
		{
			name:  "unknown field",
			files: map[string]string{"a.yaml": strings.Replace(invariants, "status:", "statuz:", 1)},
			want:  "field statuz not found",
		},
		{
			name:  "invalid document ID",
			files: map[string]string{"a.yaml": strings.Replace(oauth21, "document: OAUTH21D16", "document: oauth21", 1)},
			want:  "invalid document ID",
		},
		{
			name:  "duplicate document",
			files: map[string]string{"a.yaml": invariants, "b.yaml": invariants},
			want:  `document "INV": duplicate`,
		},
		{
			name:  "missing source",
			files: map[string]string{"a.yaml": strings.Replace(oauth21, "source: specs/draft-ietf-oauth-v2-1-16.txt\n", "", 1)},
			want:  "source must be a relative path",
		},
		{
			name:  "ID not matching section",
			files: map[string]string{"a.yaml": strings.Replace(oauth21, `section: "4.1"`, `section: "4.2"`, 1)},
			want:  "OAUTH21D16-4.1-01: ID does not match",
		},
		{
			name:  "ID without sequence",
			files: map[string]string{"a.yaml": strings.Replace(oauth21, "id: OAUTH21D16-4.1-01", "id: OAUTH21D16-4.1-1", 1)},
			want:  "ID does not match",
		},
		{
			name:  "invariant with section",
			files: map[string]string{"a.yaml": strings.Replace(invariants, "keyword:", "section: \"1\"\n    keyword:", 1)},
			want:  "INV-0001: ID does not match",
		},
		{
			name:  "duplicate requirement",
			files: map[string]string{"a.yaml": oauth21 + strings.SplitAfter(oauth21, "requirements:\n")[1]},
			want:  "OAUTH21D16-4.1-01: duplicate",
		},
		{
			name:  "unknown keyword",
			files: map[string]string{"a.yaml": strings.Replace(invariants, "keyword: MUST", "keyword: must", 1)},
			want:  `unknown keyword "must"`,
		},
		{
			name:  "unknown status",
			files: map[string]string{"a.yaml": strings.Replace(invariants, "status: applicable", "status: done", 1)},
			want:  `unknown status "done"`,
		},
		{
			name:  "missing text",
			files: map[string]string{"a.yaml": strings.Replace(invariants, "text: An authorization code issues tokens at most once.", `text: ""`, 1)},
			want:  "INV-0001: missing text",
		},
		{
			name:  "superseded without successor",
			files: map[string]string{"a.yaml": strings.Replace(rfc6749, "    superseded_by: [OAUTH21D16-4.1-01]\n", "", 1)},
			want:  "RFC6749-4.2-01: superseded_by must be set",
		},
		{
			name:  "successor without superseded status",
			files: map[string]string{"a.yaml": invariants + "    superseded_by: [INV-0001]\n"},
			want:  "INV-0001: superseded_by must be set",
		},
		{
			name:  "shared text without statement",
			files: map[string]string{"a.yaml": invariants + "  - id: INV-0002\n    keyword: MUST\n    text: An authorization code issues tokens at most once.\n    statement: Tokens are issued once.\n    status: applicable\n"},
			want:  "INV-0001: shares its text with another requirement and has no statement",
		},
		{
			name:  "dangling successor",
			files: map[string]string{"a.yaml": rfc6749},
			want:  `superseded_by "OAUTH21D16-4.1-01" is not another requirement`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := load(tt.files)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestLoadMissingDirectory(t *testing.T) {
	if _, err := Load(os.DirFS(filepath.Join(t.TempDir(), "missing"))); err == nil {
		t.Fatal("got nil error for a missing directory")
	}
}

func TestLoadSkipsDirectories(t *testing.T) {
	fsys := fstest.MapFS{
		"invariants.yaml":   {Data: []byte(invariants)},
		"nested/bad.yaml":   {Data: []byte("not: valid")},
		"drafts.yaml/x.txt": {Data: []byte("")},
	}
	c, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Documents) != 1 {
		t.Fatalf("got %d documents, want 1", len(c.Documents))
	}
}

func TestKeywordAbsolute(t *testing.T) {
	for _, k := range keywords {
		want := k == Must || k == MustNot || k == Required || k == Shall || k == ShallNot
		if got := k.Absolute(); got != want {
			t.Errorf("%s.Absolute() = %v, want %v", k, got, want)
		}
	}
}
