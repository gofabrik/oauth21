package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	conformanceDir  = "conformance"
	catalogDir      = "conformance/catalog"
	uncoveredFile   = "conformance/catalog/uncovered.txt"
	coversDirective = "//conformance:covers"
)

// Coverage maps catalog IDs to the conformance tests that cover them.
type Coverage struct {
	catalog   *Catalog
	gate      map[string]bool
	tests     map[string][]string
	uncovered []string
	base      map[string]bool
}

// directive is one //conformance:covers comment.
type directive struct {
	pos  string
	test string
	ids  []string
}

// coverRepo reports the coverage of the repository in dir and gates it, against the repository in base if it is set.
func coverRepo(dir, base string, stdout io.Writer) error {
	var baseFS fs.FS
	if base != "" {
		baseFS = os.DirFS(base)
	}
	c, err := Cover(os.DirFS(dir), baseFS)
	if err != nil {
		return err
	}
	if err := c.Report(stdout); err != nil {
		return err
	}
	return c.Gate()
}

// Cover loads the catalog of the repository in fsys and scans its Go files for directives.
// A non-nil base is the earlier repository the known-uncovered list may only shrink from.
func Cover(fsys, base fs.FS) (*Coverage, error) {
	cat, list, err := loadCatalog(fsys)
	if err != nil {
		return nil, err
	}
	if err := cat.Validate(); err != nil {
		return nil, err
	}
	if err := checkGroups(list); err != nil {
		return nil, err
	}
	c := &Coverage{catalog: cat, gate: map[string]bool{}, tests: map[string][]string{}, uncovered: parseUncovered(list)}
	for _, d := range cat.Documents {
		for _, r := range d.Requirements {
			c.gate[r.ID] = gated(d.ID, r)
		}
	}
	if c.base, err = baseListed(base); err != nil {
		return nil, err
	}

	var errs []error
	err = fs.WalkDir(fsys, ".", func(name string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name != "." && ignored(e.Name()) {
			if e.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if e.IsDir() || path.Ext(name) != ".go" {
			return nil
		}
		src, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		if module(fsys, path.Dir(name)) != conformanceDir {
			for _, pos := range mentions(name, src) {
				errs = append(errs, fmt.Errorf("%s: directive outside the conformance module", pos))
			}
			return nil
		}
		ds, err := directives(name, src)
		if err != nil {
			errs = append(errs, err)
		}
		for _, d := range ds {
			if d.test == "" {
				errs = append(errs, fmt.Errorf("%s: directive not on a test function", d.pos))
				continue
			}
			for _, id := range d.ids {
				if _, ok := c.gate[id]; !ok {
					errs = append(errs, fmt.Errorf("%s: unknown ID %q", d.pos, id))
					continue
				}
				c.tests[id] = append(c.tests[id], d.test)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

// Tests returns the test functions that cover id.
func (c *Coverage) Tests(id string) []string {
	return c.tests[id]
}

func (c *Coverage) covered(id string) bool {
	return len(c.tests[id]) > 0
}

// Report writes the coverage of applicable and gated Requirements per document and keyword, and the gaps not gated.
func (c *Coverage) Report(w io.Writer) error {
	var (
		b    strings.Builder
		gaps []Requirement
	)
	for _, d := range c.catalog.Documents {
		fmt.Fprintln(&b, d.ID)
		for _, k := range keywords {
			var covered, uncovered int
			for _, r := range d.Requirements {
				switch {
				case r.Keyword != k || (r.Status != Applicable && !c.gate[r.ID]):
				case c.covered(r.ID):
					covered++
				default:
					uncovered++
					if !c.gate[r.ID] {
						gaps = append(gaps, r)
					}
				}
			}
			if covered+uncovered > 0 {
				fmt.Fprintf(&b, "  %-15s %d covered, %d uncovered\n", k, covered, uncovered)
			}
		}
	}
	if len(gaps) > 0 {
		fmt.Fprintln(&b, "\nUncovered, not gated:")
		for _, r := range gaps {
			fmt.Fprintf(&b, "  %s %s\n", r.ID, r.Keyword)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Gate reports gated Requirements that are uncovered and not listed, and listed ones that are covered or new to the list.
func (c *Coverage) Gate() error {
	var errs []error
	listed := map[string]bool{}
	for _, id := range c.uncovered {
		listed[id] = true
		if c.covered(id) {
			errs = append(errs, fmt.Errorf("%s: covered but on the known-uncovered list", id))
		}
		if wasListed, ok := c.base[id]; ok && !wasListed {
			errs = append(errs, fmt.Errorf("%s: added to the known-uncovered list", id))
		}
	}
	for _, d := range c.catalog.Documents {
		for _, r := range d.Requirements {
			if c.gate[r.ID] && !c.covered(r.ID) && !listed[r.ID] {
				errs = append(errs, fmt.Errorf("%s: uncovered and not on the known-uncovered list", r.ID))
			}
		}
	}
	return errors.Join(errs...)
}

// gated reports whether r is an applicable absolute Requirement or a Security Invariant.
func gated(doc string, r Requirement) bool {
	return doc == InvariantsDocument || (r.Status == Applicable && r.Keyword.Absolute())
}

// loadCatalog reads the catalog, unvalidated, and the known-uncovered list of the repository in fsys.
func loadCatalog(fsys fs.FS) (*Catalog, []byte, error) {
	sub, err := fs.Sub(fsys, catalogDir)
	if err != nil {
		return nil, nil, err
	}
	cat, err := read(sub)
	if err != nil {
		return nil, nil, err
	}
	list, err := fs.ReadFile(fsys, uncoveredFile)
	if err != nil {
		return nil, nil, err
	}
	return cat, list, nil
}

// baseListed maps the IDs of the base catalog, except those out-of-scope for an excluded feature, to whether they are on its known-uncovered list.
// It is nil when there is no base or the base has no list.
func baseListed(base fs.FS) (map[string]bool, error) {
	if base == nil {
		return nil, nil
	}
	if _, err := fs.Stat(base, catalogDir); err != nil {
		return nil, fmt.Errorf("base: %w", err)
	}
	if _, err := fs.Stat(base, uncoveredFile); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	cat, list, err := loadCatalog(base)
	if err != nil {
		return nil, fmt.Errorf("base: %w", err)
	}
	m := map[string]bool{}
	for _, d := range cat.Documents {
		for _, r := range d.Requirements {
			if r.Reason != Excluded {
				m[r.ID] = false
			}
		}
	}
	for _, id := range parseUncovered(list) {
		if _, ok := m[id]; ok {
			m[id] = true
		}
	}
	return m, nil
}

// parseUncovered returns the IDs of a known-uncovered list, one per line, skipping blanks and "#" comments.
func parseUncovered(data []byte) []string {
	var ids []string
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			ids = append(ids, line)
		}
	}
	return ids
}

// checkGroups returns an error for each ID of a known-uncovered list that is not under a "# NN: <title>" ticket heading.
func checkGroups(data []byte) error {
	var (
		errs  []error
		group bool
		n     int
	)
	for line := range strings.Lines(string(data)) {
		n++
		line = strings.TrimSpace(line)
		switch {
		case ticketHeading(line):
			group = true
		case numberedComment(line):
			group = false
			errs = append(errs, fmt.Errorf("%s:%d: malformed ticket heading %q", uncoveredFile, n, line))
		case line == "" || strings.HasPrefix(line, "#"):
		case !group:
			errs = append(errs, fmt.Errorf("%s:%d: %s outside a ticket group", uncoveredFile, n, line))
		}
	}
	return errors.Join(errs...)
}

// ticketHeading reports whether line is a "# NN: <title>" ticket heading, with at least two digits.
func ticketHeading(line string) bool {
	rest, ok := strings.CutPrefix(line, "# ")
	if !ok {
		return false
	}
	num, title, ok := strings.Cut(rest, ": ")
	return ok && len(num) >= 2 && strings.Trim(num, "0123456789") == "" && title != ""
}

// numberedComment reports whether line is a comment whose first word starts with a digit and has a colon, as a ticket heading does.
func numberedComment(line string) bool {
	rest, ok := strings.CutPrefix(line, "#")
	fields := strings.Fields(rest)
	return ok && len(fields) > 0 && fields[0][0] >= '0' && fields[0][0] <= '9' && strings.Contains(fields[0], ":")
}

// ignored reports whether the go command always ignores a file or directory with this name.
func ignored(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata"
}

// module returns the directory of the nearest go.mod at or above dir, or "" if there is none.
func module(fsys fs.FS, dir string) string {
	for {
		if _, err := fs.Stat(fsys, path.Join(dir, "go.mod")); err == nil {
			return dir
		}
		if dir == "." {
			return ""
		}
		dir = path.Dir(dir)
	}
}

// isDirective reports whether a comment is meant as a directive, well-formed or not.
func isDirective(comment string) bool {
	return strings.HasPrefix(strings.TrimSpace(comment[2:]), "conformance:covers")
}

// mentions returns the positions of the directives in src, which need not be valid Go.
func mentions(name string, src []byte) []string {
	fset := token.NewFileSet()
	var s scanner.Scanner
	s.Init(fset.AddFile(name, -1, len(src)), src, nil, scanner.ScanComments)
	var out []string
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return out
		}
		if tok == token.COMMENT && isDirective(lit) {
			out = append(out, fmt.Sprintf("%s:%d", name, fset.Position(pos).Line))
		}
	}
}

// directives returns the directives in the Go source src, with the test function each is on.
func directives(name string, src []byte) ([]directive, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	tests := map[*ast.Comment]string{}
	if strings.HasSuffix(name, "_test.go") {
		testing := importName(f, "testing")
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Doc == nil || !isTest(fn, testing) {
				continue
			}
			for _, c := range fn.Doc.List {
				tests[c] = fn.Name.Name
			}
		}
	}

	var (
		out  []directive
		errs []error
	)
	for _, g := range f.Comments {
		for _, c := range g.List {
			if !isDirective(c.Text) {
				continue
			}
			pos := fmt.Sprintf("%s:%d", name, fset.Position(c.Pos()).Line)
			fields := strings.Fields(c.Text)
			if fields[0] != coversDirective || len(fields) == 1 {
				errs = append(errs, fmt.Errorf("%s: malformed directive %q", pos, c.Text))
				continue
			}
			out = append(out, directive{pos: pos, test: tests[c], ids: fields[1:]})
		}
	}
	return out, errors.Join(errs...)
}

// importName returns the name the file f uses for the package with this import path, or "".
func importName(f *ast.File, importPath string) string {
	for _, imp := range f.Imports {
		if imp.Path.Value == `"`+importPath+`"` {
			if imp.Name != nil {
				return imp.Name.Name
			}
			return path.Base(importPath)
		}
	}
	return ""
}

// isTest reports whether go test runs fn as a test: func TestXxx(*testing.T), other than TestMain.
func isTest(fn *ast.FuncDecl, testing string) bool {
	rest, ok := strings.CutPrefix(fn.Name.Name, "Test")
	if r, _ := utf8.DecodeRuneInString(rest); !ok || unicode.IsLower(r) || fn.Name.Name == "TestMain" {
		return false
	}
	t := fn.Type
	if fn.Recv != nil || t.TypeParams != nil || t.Results != nil || len(t.Params.List) != 1 || len(t.Params.List[0].Names) > 1 {
		return false
	}
	star, ok := t.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == testing && sel.Sel.Name == "T"
}
