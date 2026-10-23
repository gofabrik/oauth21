package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// module writes a module named example.com/core with files to a temporary directory.
func module(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if _, ok := files["go.mod"]; !ok {
		files["go.mod"] = "module example.com/core\n\ngo 1.26\n"
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRunAcceptsLayers(t *testing.T) {
	dir := module(t, map[string]string{
		"core.go":                       "package core\n\nimport (\n\t_ \"example.com/core/internal/protocol\"\n\t_ \"example.com/core/internal/wire\"\n\t_ \"example.com/core/store\"\n)\n",
		"internal/protocol/protocol.go": "package protocol\n\nimport _ \"example.com/core/internal/helper\"\n",
		"internal/helper/helper.go":     "package helper\n",
		"internal/wire/wire.go":         "package wire\n\nimport _ \"net/http\"\n",
		"store/store.go":                "package store\n",
	})
	var out bytes.Buffer
	if code := run(dir, &out); code != 0 || out.Len() > 0 {
		t.Fatalf("got exit status %d and output %q, want 0 and none", code, out.String())
	}
}

func TestRunRejectsIndirectLayerImports(t *testing.T) {
	tests := []struct{ layer, dep string }{
		{"internal/protocol", "example.com/core"},
		{"internal/protocol", "example.com/core/internal/wire"},
		{"internal/protocol", "example.com/core/store"},
		{"internal/protocol", "example.com/core/memstore"},
		{"internal/protocol", "example.com/core/storetest/kit"},
		{"internal/wire", "example.com/core"},
		{"internal/wire", "example.com/core/store"},
		{"internal/wire", "example.com/core/memstore"},
		{"internal/wire", "example.com/core/storetest/kit"},
	}
	for _, tt := range tests {
		t.Run(tt.layer+"->"+tt.dep, func(t *testing.T) {
			dir := module(t, map[string]string{
				"core.go":                   "package core\n",
				"internal/wire/doc.go":      "package wire\n",
				"store/store.go":            "package store\n",
				"memstore/memstore.go":      "package memstore\n",
				"storetest/kit/kit.go":      "package kit\n",
				"internal/helper/helper.go": "package helper\n\nimport _ \"" + tt.dep + "\"\n",
				tt.layer + "/doc.go":        "package layer\n\nimport _ \"example.com/core/internal/helper\"\n",
			})
			var out bytes.Buffer
			code := run(dir, &out)
			want := "archlint: example.com/core/" + tt.layer + " depends on " + tt.dep + "\n"
			if code != 1 || out.String() != want {
				t.Fatalf("got exit status %d and output %q, want 1 and %q", code, out.String(), want)
			}
		})
	}
}

func TestRunRejectsNonStdlibImports(t *testing.T) {
	dir := module(t, map[string]string{
		"go.mod":     "module example.com/core\n\ngo 1.26\n\nrequire example.com/ext v0.0.0\n\nreplace example.com/ext => ./ext\n",
		"core.go":    "package core\n\nimport _ \"example.com/ext\"\n",
		"ext/go.mod": "module example.com/ext\n",
		"ext/ext.go": "package ext\n",
	})
	var out bytes.Buffer
	if code := run(dir, &out); code != 1 || out.String() != "archlint: non-stdlib import example.com/ext\n" {
		t.Fatalf("got exit status %d and output %q, want a non-stdlib import", code, out.String())
	}
}

func TestRunFailsWithoutModule(t *testing.T) {
	var out bytes.Buffer
	if code := run(t.TempDir(), &out); code != 2 {
		t.Fatalf("got exit status %d, want 2", code)
	}
}

func TestRunRejectsIndirectProtocolIO(t *testing.T) {
	dir := module(t, map[string]string{
		"internal/protocol/doc.go":  "package protocol\n\nimport _ \"example.com/core/internal/helper\"\n",
		"internal/helper/helper.go": "package helper\n\nimport _ \"net/http\"\n",
	})
	var out bytes.Buffer
	code := run(dir, &out)
	if code != 1 || !strings.Contains(out.String(), "archlint: example.com/core/internal/protocol depends on net/http\n") {
		t.Fatalf("got exit status %d and output %q, want a layer violation", code, out.String())
	}
}
