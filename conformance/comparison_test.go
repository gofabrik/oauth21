package conformance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// variableTime are the comparison functions that return as soon as their arguments differ.
var variableTime = map[string]bool{
	"bytes.Equal": true, "bytes.EqualFold": true, "bytes.Compare": true,
	"strings.EqualFold": true, "strings.Compare": true,
	"slices.Equal": true, "slices.Compare": true, "reflect.DeepEqual": true,
}

// TestSecretsComparedInConstantTime checks in the source of the core module that the functions comparing a presented Client secret or code verifier with the expected value do so only through crypto/subtle.
//
//conformance:covers INV-0008
func TestSecretsComparedInConstantTime(t *testing.T) {
	for _, c := range []struct{ dir, fn string }{
		{"..", "PBKDF2.Verify"},
		{"../internal/protocol", "verifyPKCE"},
	} {
		t.Run(c.fn, func(t *testing.T) {
			fset := token.NewFileSet()
			fn, consts := parseFunc(t, fset, c.dir, c.fn)
			constant := func(e ast.Expr) bool {
				switch e := ast.Unparen(e).(type) {
				case *ast.BasicLit:
					return true
				case *ast.Ident:
					return e.Name == "nil" || e.Name == "true" || e.Name == "false" || consts[e.Name]
				case *ast.CallExpr:
					f, ok := e.Fun.(*ast.Ident)
					return ok && f.Name == "len"
				}
				return false
			}
			subtle := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BinaryExpr:
					switch n.Op {
					case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
						if !constant(n.X) && !constant(n.Y) {
							t.Errorf("%s: comparison in variable time", fset.Position(n.Pos()))
						}
					}
				case *ast.SwitchStmt:
					if n.Tag != nil && !constant(n.Tag) {
						t.Errorf("%s: switch in variable time", fset.Position(n.Pos()))
					}
				case *ast.CallExpr:
					sel, ok := n.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkg, ok := sel.X.(*ast.Ident)
					if !ok {
						return true
					}
					switch name := pkg.Name + "." + sel.Sel.Name; {
					case name == "subtle.ConstantTimeCompare":
						subtle = true
					case variableTime[name]:
						t.Errorf("%s: %s in variable time", fset.Position(n.Pos()), name)
					}
				}
				return true
			})
			if !subtle {
				t.Errorf("%s does not compare through subtle.ConstantTimeCompare", c.fn)
			}
		})
	}
}

// parseFunc returns the function or method name of the package in dir and the names of the package's constants.
func parseFunc(t *testing.T, fset *token.FileSet, dir, name string) (*ast.FuncDecl, map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	consts := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if funcName(d) == name {
					fn = d
				}
			case *ast.GenDecl:
				if d.Tok != token.CONST {
					continue
				}
				for _, s := range d.Specs {
					for _, n := range s.(*ast.ValueSpec).Names {
						consts[n.Name] = true
					}
				}
			}
		}
	}
	if fn == nil || fn.Body == nil {
		t.Fatalf("%s not found in %s", name, dir)
	}
	return fn, consts
}

func funcName(d *ast.FuncDecl) string {
	if d.Recv == nil {
		return d.Name.Name
	}
	typ := d.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + d.Name.Name
	}
	return ""
}
