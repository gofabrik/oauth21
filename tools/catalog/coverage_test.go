package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"unicode"
)

const coverageCatalog = `
document: RFC7636
title: Proof Key for Code Exchange by OAuth Public Clients
source: ../specs/rfc7636.txt
requirements:
  - id: RFC7636-4.4-01
    section: "4.4"
    keyword: MUST
    text: The server MUST support S256.
    status: applicable
  - id: RFC7636-4.4-02
    section: "4.4"
    keyword: MUST
    text: The server MUST reject plain.
    status: applicable
  - id: RFC7636-4.5-01
    section: "4.5"
    keyword: MAY
    text: The server MAY log failures.
    status: applicable
  - id: RFC7636-4.5-02
    section: "4.5"
    keyword: SHOULD
    text: The server SHOULD accept plain.
    status: deviates
    note: spec.md accepts S256 only.
  - id: RFC7636-4.6-01
    section: "4.6"
    keyword: MUST
    text: The client MUST send a verifier.
    status: out-of-scope
    reason: client-requirement
`

const coverageTests = `package conformance

import "testing"

// TestS256 checks the S256 method.
//
//conformance:covers RFC7636-4.4-01
func TestS256(t *testing.T) {}

//conformance:covers RFC7636-4.4-01
func TestS256Again(t *testing.T) {}

//conformance:covers INV-0001
func TestInvariant(t *testing.T) {}

func TestUncovering(t *testing.T) {}
`

// withoutInvariant is coverageTests without the directive that covers INV-0001.
var withoutInvariant = strings.Replace(coverageTests, "//conformance:covers INV-0001\n", "", 1)

// bothListed is a known-uncovered list with RFC7636-4.4-02 and INV-0001.
const bothListed = "# 01: t\nRFC7636-4.4-02\nINV-0001\n"

// gateRecommended is a gate file that gates recommended Requirements.
const gateRecommended = "recommended: true\n"

// applicableShould is coverageCatalog with its recommended Requirement applicable.
var applicableShould = strings.Replace(coverageCatalog, "status: deviates", "status: applicable", 1)

// testFile returns a conformance test file with body after its imports, which end on line 4.
func testFile(body string) string {
	return "package conformance\n\nimport \"testing\"\n" + body
}

// repo returns a repository with a valid catalog, changed by files; an empty value removes the file.
func repo(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{
		"go.mod":                              {Data: []byte("module example.com/core\n")},
		"conformance/go.mod":                  {Data: []byte("module example.com/conformance\n")},
		"conformance/catalog/rfc7636.yaml":    {Data: []byte(coverageCatalog)},
		"conformance/catalog/invariants.yaml": {Data: []byte(invariants)},
		"conformance/catalog/gate.yaml":       {Data: []byte(gateRecommended)},
		"conformance/catalog/uncovered.txt":   {Data: []byte("# 01: t\nRFC7636-4.4-02\n")},
		"conformance/pkce_test.go":            {Data: []byte(coverageTests)},
	}
	for name, data := range files {
		if data == "" {
			delete(fsys, name)
			continue
		}
		fsys[name] = &fstest.MapFile{Data: []byte(data)}
	}
	return fsys
}

func TestCoverFindsDirectives(t *testing.T) {
	c, err := Cover(repo(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"RFC7636-4.4-01": {"TestS256", "TestS256Again"},
		"INV-0001":       {"TestInvariant"},
	}
	for id, tests := range want {
		if got := c.Tests(id); !slices.Equal(got, tests) {
			t.Errorf("Tests(%s) = %v, want %v", id, got, tests)
		}
	}
	if got := c.Tests("RFC7636-4.4-02"); len(got) != 0 {
		t.Errorf("Tests(RFC7636-4.4-02) = %v, want none", got)
	}
}

func TestCoverAcceptsTestSignatures(t *testing.T) {
	tests := map[string]string{
		"renamed testing import": "package conformance\n\nimport tt \"testing\"\n\n//conformance:covers RFC7636-4.4-02\nfunc TestX(t *tt.T) {}\n",
		"unnamed parameter":      testFile("\n//conformance:covers RFC7636-4.4-02\nfunc TestX(*testing.T) {}\n"),
		"name Test":              testFile("\n//conformance:covers RFC7636-4.4-02\nfunc Test(t *testing.T) {}\n"),
		"name Test_x":            testFile("\n//conformance:covers RFC7636-4.4-02\nfunc Test_x(t *testing.T) {}\n"),
	}
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			c, err := Cover(repo(map[string]string{"conformance/x_test.go": src}), nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.Tests("RFC7636-4.4-02"); len(got) != 1 {
				t.Fatalf("Tests(RFC7636-4.4-02) = %v, want one test", got)
			}
		})
	}
}

func TestCoverInvalid(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name:  "unknown ID",
			files: map[string]string{"conformance/x_test.go": testFile("\n//conformance:covers RFC7636-9-01\nfunc TestX(t *testing.T) {}\n")},
			want:  `conformance/x_test.go:5: unknown ID "RFC7636-9-01"`,
		},
		{
			name:  "outside the conformance module",
			files: map[string]string{"server/x_test.go": "package server\n\n//conformance:covers INV-0001\nfunc TestX() {}\n"},
			want:  "server/x_test.go:3: directive outside the conformance module",
		},
		{
			name:  "outside the conformance module in invalid Go",
			files: map[string]string{"server/x.go": "package\n\n//conformance:covers INV-0001\n"},
			want:  "server/x.go:3: directive outside the conformance module",
		},
		{
			name:  "in a nested module",
			files: map[string]string{"conformance/x/go.mod": "module x\n", "conformance/x/x_test.go": testFile("\n//conformance:covers INV-0001\nfunc TestX(t *testing.T) {}\n")},
			want:  "conformance/x/x_test.go:5: directive outside the conformance module",
		},
		{
			name:  "without a conformance module",
			files: map[string]string{"conformance/go.mod": ""},
			want:  "conformance/pkce_test.go:7: directive outside the conformance module",
		},
		{
			name:  "not on a function",
			files: map[string]string{"conformance/x_test.go": testFile("\n//conformance:covers INV-0001\nvar x int\n")},
			want:  "conformance/x_test.go:5: directive not on a test function",
		},
		{
			name:  "in a non-test file",
			files: map[string]string{"conformance/x.go": testFile("\n//conformance:covers INV-0001\nfunc TestX(t *testing.T) {}\n")},
			want:  "conformance/x.go:5: directive not on a test function",
		},
		{
			name:  "inside a function body",
			files: map[string]string{"conformance/x_test.go": testFile("\nfunc TestX(t *testing.T) {\n\t//conformance:covers INV-0001\n}\n")},
			want:  "conformance/x_test.go:6: directive not on a test function",
		},
		{
			name:  "without IDs",
			files: map[string]string{"conformance/x_test.go": testFile("\n//conformance:covers\nfunc TestX(t *testing.T) {}\n")},
			want:  "conformance/x_test.go:5: malformed directive",
		},
		{
			name:  "with several IDs",
			files: map[string]string{"conformance/x_test.go": testFile("\n//conformance:covers RFC7636-4.4-02 INV-0001\nfunc TestX(t *testing.T) {}\n")},
			want:  "conformance/x_test.go:5: directive with more than one ID",
		},
		{
			name:  "several directives on a test",
			files: map[string]string{"conformance/x_test.go": testFile("\n//conformance:covers RFC7636-4.4-02\n//conformance:covers INV-0001\nfunc TestX(t *testing.T) {}\n")},
			want:  "conformance/x_test.go:6: TestX has more than one directive",
		},
		{
			name:  "misspelled",
			files: map[string]string{"conformance/x_test.go": testFile("\n//conformance:coversINV-0001\nfunc TestX(t *testing.T) {}\n")},
			want:  "conformance/x_test.go:5: malformed directive",
		},
		{
			name:  "with a space",
			files: map[string]string{"conformance/x_test.go": testFile("\n// conformance:covers INV-0001\nfunc TestX(t *testing.T) {}\n")},
			want:  "conformance/x_test.go:5: malformed directive",
		},
		{
			name:  "in a block comment",
			files: map[string]string{"conformance/x_test.go": testFile("\n/* conformance:covers INV-0001 */\nfunc TestX(t *testing.T) {}\n")},
			want:  "conformance/x_test.go:5: malformed directive",
		},
		{
			name:  "unparsable Go file",
			files: map[string]string{"conformance/x_test.go": "package"},
			want:  "conformance/x_test.go:1",
		},
		{
			name:  "ID outside a group",
			files: map[string]string{"conformance/catalog/uncovered.txt": "RFC7636-4.4-02\n"},
			want:  "conformance/catalog/uncovered.txt:1: RFC7636-4.4-02 outside a ticket group",
		},
		{
			name:  "ID under a comment",
			files: map[string]string{"conformance/catalog/uncovered.txt": "# Known uncovered.\nRFC7636-4.4-02\n"},
			want:  "conformance/catalog/uncovered.txt:2: RFC7636-4.4-02 outside a ticket group",
		},
		{
			name:  "ID under a heading without a title",
			files: map[string]string{"conformance/catalog/uncovered.txt": "# 25:\nRFC7636-4.4-02\n"},
			want:  "conformance/catalog/uncovered.txt:2: RFC7636-4.4-02 outside a ticket group",
		},
		{
			name:  "ID under a heading without a number",
			files: map[string]string{"conformance/catalog/uncovered.txt": "# 25a: title\nRFC7636-4.4-02\n"},
			want:  "conformance/catalog/uncovered.txt:2: RFC7636-4.4-02 outside a ticket group",
		},
		{
			name:  "heading without a title after a group",
			files: map[string]string{"conformance/catalog/uncovered.txt": "# 25: title\nRFC7636-4.4-01\n# 26:\nRFC7636-4.4-02\n"},
			want:  `conformance/catalog/uncovered.txt:3: malformed ticket heading "# 26:"`,
		},
		{
			name:  "heading without a number after a group",
			files: map[string]string{"conformance/catalog/uncovered.txt": "# 25: title\nRFC7636-4.4-01\n# 26a: title\nRFC7636-4.4-02\n"},
			want:  `conformance/catalog/uncovered.txt:3: malformed ticket heading "# 26a: title"`,
		},
		{
			name:  "heading with one digit",
			files: map[string]string{"conformance/catalog/uncovered.txt": "# 3: title\nRFC7636-4.4-02\n"},
			want:  `conformance/catalog/uncovered.txt:1: malformed ticket heading "# 3: title"`,
		},
		{
			name:  "invalid catalog",
			files: map[string]string{"conformance/catalog/invariants.yaml": "document: inv\n"},
			want:  "invalid document ID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Cover(repo(tt.files), nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestCoverRejectsNonTests(t *testing.T) {
	tests := map[string]string{
		"helper":            "func helper(t *testing.T) {}",
		"TestMain":          "func TestMain(m *testing.M) {}",
		"TestMain with T":   "func TestMain(t *testing.T) {}",
		"lowercase after":   "func Testable(t *testing.T) {}",
		"no parameter":      "func TestX() {}",
		"wrong parameter":   "func TestX(b *testing.B) {}",
		"not a pointer":     "func TestX(t testing.T) {}",
		"two parameters":    "func TestX(t, u *testing.T) {}",
		"result":            "func TestX(t *testing.T) error { return nil }",
		"method":            "func (s) TestX(t *testing.T) {}",
		"type parameter":    "func TestX[P any](t *testing.T) {}",
		"other package T":   "func TestX(t *other.T) {}",
		"testing not named": "func TestX(t *T) {}",
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) {
			src := testFile("\n//conformance:covers INV-0001\n" + fn + "\n")
			_, err := Cover(repo(map[string]string{"conformance/x_test.go": src}), nil)
			want := "conformance/x_test.go:5: directive not on a test function"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got error %v, want it to contain %q", err, want)
			}
		})
	}
}

func TestCoverSkipsIgnoredFiles(t *testing.T) {
	covering := testFile("\n//conformance:covers RFC7636-4.4-02\nfunc TestX(t *testing.T) {}\n")
	c, err := Cover(repo(map[string]string{
		".git/x_test.go":                 covering,
		"tools/x/testdata/x_test.go":     covering,
		"conformance/_disabled_test.go":  covering,
		"conformance/.hidden_test.go":    covering,
		"conformance/_old/x_test.go":     covering,
		"conformance/testdata/x_test.go": covering,
		"conformance/catalog/notes.md":   "//conformance:covers RFC7636-9-01",
		"server/x.go":                    "package",
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Tests("RFC7636-4.4-02"); len(got) != 0 {
		t.Fatalf("Tests(RFC7636-4.4-02) = %v, want none", got)
	}
}

func TestGatePasses(t *testing.T) {
	c, err := Cover(repo(map[string]string{
		"conformance/catalog/uncovered.txt": "# Known uncovered.\n\n# 25: authenticate first\n# 2 more to come.\nRFC7636-4.4-02\n",
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Gate(); err != nil {
		t.Fatal(err)
	}
}

func TestGateWithoutRecommended(t *testing.T) {
	c, err := Cover(repo(map[string]string{
		"conformance/catalog/rfc7636.yaml": applicableShould,
		"conformance/catalog/gate.yaml":    "",
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Gate(); err != nil {
		t.Fatal(err)
	}
}

func TestGateFails(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name:  "uncovered and not listed",
			files: map[string]string{"conformance/catalog/uncovered.txt": "\n"},
			want:  "RFC7636-4.4-02: uncovered and not on the known-uncovered list",
		},
		{
			name:  "invariant uncovered",
			files: map[string]string{"conformance/pkce_test.go": withoutInvariant},
			want:  "INV-0001: uncovered and not on the known-uncovered list",
		},
		{
			name: "invariant uncovered whatever its status",
			files: map[string]string{
				"conformance/pkce_test.go":            withoutInvariant,
				"conformance/catalog/invariants.yaml": strings.Replace(invariants, "status: applicable", "status: out-of-scope\n    reason: client-requirement", 1),
			},
			want: "INV-0001: uncovered and not on the known-uncovered list",
		},
		{
			name:  "recommended uncovered and not listed",
			files: map[string]string{"conformance/catalog/rfc7636.yaml": applicableShould},
			want:  "RFC7636-4.5-02: uncovered and not on the known-uncovered list",
		},
		{
			name:  "listed but covered",
			files: map[string]string{"conformance/x_test.go": testFile("\n//conformance:covers RFC7636-4.4-02\nfunc TestX(t *testing.T) {}\n")},
			want:  "RFC7636-4.4-02: covered but on the known-uncovered list",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Cover(repo(tt.files), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Gate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestGateRatchet(t *testing.T) {
	uncoveredRepo := map[string]string{
		"conformance/pkce_test.go":          withoutInvariant,
		"conformance/catalog/uncovered.txt": bothListed,
	}
	tests := []struct {
		name string
		base map[string]string
		want string
	}{
		{
			name: "listed at the base",
			base: map[string]string{"conformance/catalog/uncovered.txt": bothListed},
		},
		{
			name: "added to the list",
			want: "INV-0001: added to the known-uncovered list",
		},
		{
			name: "new to the catalog",
			base: map[string]string{"conformance/catalog/invariants.yaml": strings.Replace(invariants, "INV-0001", "INV-0002", 1)},
		},
		{
			name: "base without a list",
			base: map[string]string{"conformance/catalog/uncovered.txt": ""},
		},
		{
			name: "base written before a catalog rule",
			base: map[string]string{
				"conformance/catalog/uncovered.txt": "RFC7636-4.4-02\nINV-0001\n",
				"conformance/catalog/rfc7636.yaml":  strings.Replace(coverageCatalog, "    reason: client-requirement\n", "", 1),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Cover(repo(uncoveredRepo), repo(tt.base))
			if err != nil {
				t.Fatal(err)
			}
			err = c.Gate()
			if tt.want == "" && err != nil {
				t.Fatal(err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("got error %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestGateRatchetNewlyGated(t *testing.T) {
	head := repo(map[string]string{
		"conformance/catalog/rfc7636.yaml":  strings.Replace(coverageCatalog, "status: out-of-scope\n    reason: client-requirement", "status: applicable", 1),
		"conformance/catalog/uncovered.txt": "# 01: t\nRFC7636-4.4-02\nRFC7636-4.6-01\n",
	})
	tests := []struct {
		name   string
		reason string
		want   string
	}{
		{name: "excluded at the base", reason: "reason: excluded\n    feature: dpop"},
		{name: "client-requirement at the base", reason: "reason: client-requirement", want: "RFC7636-4.6-01: added to the known-uncovered list"},
		{name: "no reason at the base", reason: "", want: "RFC7636-4.6-01: added to the known-uncovered list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := repo(map[string]string{"conformance/catalog/rfc7636.yaml": strings.Replace(coverageCatalog, "reason: client-requirement", tt.reason, 1)})
			c, err := Cover(head, base)
			if err != nil {
				t.Fatal(err)
			}
			err = c.Gate()
			if tt.want == "" && err != nil {
				t.Fatal(err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("got error %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestGateRatchetRecommendedGated(t *testing.T) {
	head := repo(map[string]string{
		"conformance/catalog/rfc7636.yaml":  applicableShould,
		"conformance/catalog/uncovered.txt": "# 01: t\nRFC7636-4.4-02\nRFC7636-4.5-02\n",
	})
	tests := []struct {
		name string
		gate string
		want string
	}{
		{name: "base without a gate file", gate: ""},
		{name: "base not gating recommended", gate: "recommended: false\n"},
		{name: "base gating recommended", gate: gateRecommended, want: "RFC7636-4.5-02: added to the known-uncovered list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := repo(map[string]string{"conformance/catalog/rfc7636.yaml": applicableShould, "conformance/catalog/gate.yaml": tt.gate})
			c, err := Cover(head, base)
			if err != nil {
				t.Fatal(err)
			}
			err = c.Gate()
			if tt.want == "" && err != nil {
				t.Fatal(err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("got error %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestGateRatchetKeepsRecommendedGated(t *testing.T) {
	c, err := Cover(repo(map[string]string{"conformance/catalog/gate.yaml": "recommended: false\n"}), repo(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Gate(); err == nil || !strings.Contains(err.Error(), "the gate no longer covers recommended Requirements") {
		t.Fatalf("got error %v, want the narrowed gate to fail", err)
	}
}

func TestCoverInvalidBase(t *testing.T) {
	bases := map[string]fstest.MapFS{
		"invalid catalog": repo(map[string]string{"conformance/catalog/invariants.yaml": "documentz: INV\n"}),
		"empty":           {},
	}
	for name, base := range bases {
		t.Run(name, func(t *testing.T) {
			if _, err := Cover(repo(nil), base); err == nil || !strings.Contains(err.Error(), "base: ") {
				t.Fatalf("got error %v, want an error about the base", err)
			}
		})
	}
}

func TestCoverMissingUncoveredList(t *testing.T) {
	if _, err := Cover(repo(map[string]string{"conformance/catalog/uncovered.txt": ""}), nil); err == nil {
		t.Fatal("got nil error for a missing known-uncovered list")
	}
}

func TestReport(t *testing.T) {
	c, err := Cover(repo(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := c.Report(&b); err != nil {
		t.Fatal(err)
	}
	want := `INV
  MUST            1 covered, 0 uncovered
RFC7636
  MUST            1 covered, 1 uncovered
  MAY             0 covered, 1 uncovered

Uncovered, not gated:
  RFC7636-4.5-01 MAY
`
	if b.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", b.String(), want)
	}
}

// writeRepo writes fsys to a new directory and returns it.
func writeRepo(t *testing.T, fsys fstest.MapFS) string {
	t.Helper()
	dir := t.TempDir()
	for name, f := range fsys {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, f.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRunCoverage(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"coverage", writeRepo(t, repo(nil))}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "INV\n") {
		t.Fatalf("got output %q, want the report", out.String())
	}
}

func TestRunCoverageFails(t *testing.T) {
	dir := writeRepo(t, repo(map[string]string{"conformance/catalog/uncovered.txt": "\n"}))
	var out bytes.Buffer
	err := run([]string{"coverage", dir}, &out)
	if err == nil || !strings.Contains(err.Error(), "RFC7636-4.4-02: uncovered") {
		t.Fatalf("got error %v, want the gate to fail", err)
	}
	if !strings.HasPrefix(out.String(), "INV\n") {
		t.Fatalf("got output %q, want the report", out.String())
	}
}

func TestRunCoverageAgainstBase(t *testing.T) {
	dir := writeRepo(t, repo(map[string]string{
		"conformance/pkce_test.go":          withoutInvariant,
		"conformance/catalog/uncovered.txt": bothListed,
	}))
	base := writeRepo(t, repo(nil))
	err := run([]string{"coverage", dir, base}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "INV-0001: added to the known-uncovered list") {
		t.Fatalf("got error %v, want the ratchet to fail", err)
	}
}

func TestRunCoverageUsage(t *testing.T) {
	for _, args := range [][]string{{"coverage"}, {"coverage", "a", "b", "c"}} {
		if err := run(args, &bytes.Buffer{}); !errors.Is(err, errUsage) {
			t.Errorf("run(%q) = %v, want the usage error", args, err)
		}
	}
}

func FuzzDirectives(f *testing.F) {
	f.Add(coverageTests)
	f.Add("package x\n\nfunc TestX() {\n\t//conformance:covers\n}\n/*\n//conformance:covers A\n*/")
	f.Add("package x\n\nimport \"testing\"\n\n//conformance:covers A B\n//conformance:covers C\n//conformance:covers D\nfunc TestX(t *testing.T) {}\n")
	f.Fuzz(func(t *testing.T, src string) {
		ds, _ := directives("x_test.go", []byte(src))
		tests := map[string]bool{}
		for _, d := range ds {
			if d.id == "" || strings.ContainsFunc(d.id, unicode.IsSpace) {
				t.Errorf("%s: invalid ID %q", d.pos, d.id)
			}
			if d.test == "" {
				continue
			}
			if !strings.HasPrefix(d.test, "Test") {
				t.Errorf("%s: %q is not a test function", d.pos, d.test)
			}
			if tests[d.test] {
				t.Errorf("%s: second directive on %s", d.pos, d.test)
			}
			tests[d.test] = true
		}
	})
}

func FuzzMentions(f *testing.F) {
	f.Add(coverageTests)
	f.Add("package\n\n/* conformance:covers\n\"//conformance:covers\" `\n")
	f.Fuzz(func(t *testing.T, src string) {
		ds, err := directives("x_test.go", []byte(src))
		if err != nil {
			return
		}
		if got := mentions("x_test.go", []byte(src)); len(got) != len(ds) {
			t.Errorf("mentions found %d directives, directives found %d", len(got), len(ds))
		}
	})
}
