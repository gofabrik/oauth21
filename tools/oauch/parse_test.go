package main

import (
	"bytes"
	"html"
	"strings"
	"testing"
)

func FuzzParseForm(f *testing.F) {
	f.Add("", "decision", "allow")
	f.Add("<p>Log in</p>", "state", `s 1&amp;"x"`)
	f.Add("<input name=outside value=1>", "redirect_uri", "https://127.0.0.1/Callback?a=<b>")
	f.Fuzz(func(t *testing.T, prefix, name, value string) {
		if name == "" || strings.Contains(strings.ToLower(prefix), "<form") {
			return
		}
		page := prefix + `<form method="post"><input type="hidden" name="request_id" value="r1"><input name="password" type="password">` +
			`<input type="hidden" name="` + html.EscapeString(name) + `" value="` + html.EscapeString(value) + `"><button>Log in</button></form>`
		form, ok := parseForm(page)
		if !ok || form.method != "post" {
			t.Fatalf("got form %+v (%v) from %q, want the post form", form, ok, page)
		}
		if got := form.values[name]; len(got) == 0 || got[len(got)-1] != value {
			t.Fatalf("got %q for %q from %q, want %q last", got, name, page, value)
		}
		if name != "request_id" && form.values.Get("request_id") != "r1" {
			t.Fatalf("got request_id %q from %q, want r1", form.values.Get("request_id"), page)
		}
	})
}

func FuzzParseFrames(f *testing.F) {
	f.Add([]byte("{}\x1e"))
	f.Add([]byte(`{"type":6}` + "\x1e" + `{"type":1,"target":"RedirectPopup","arguments":["https://as.example/authorize"]}` + "\x1e"))
	f.Add([]byte(`{"type":7,"error":"Connection closed with an error."}` + "\x1e"))
	f.Add([]byte(`{"type":1,"target":"OnMessage","arguments":[1,{"a":[]}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		msgs, err := parseFrames(b)
		if err != nil {
			return
		}
		if frames := bytes.Count(b, []byte(recordSeparator)) + 1; len(msgs) > frames {
			t.Fatalf("got %d messages from %d frames of %q", len(msgs), frames, b)
		}
	})
}

func FuzzSummarize(f *testing.F) {
	f.Add([]byte(exportJSON))
	f.Add([]byte(`[{"TestRuns":[{"TestResults":[{"TestId":"t","Outcome":-1},{"TestId":"u","Outcome":9}]}]}]`))
	f.Add([]byte(`[{"TestRuns":[]}]`))
	f.Fuzz(func(t *testing.T, export []byte) {
		summary, err := summarize(export, []string{"GET https://as.example/authorize answered 400 Bad Request without a form"})
		if err == nil && !strings.HasPrefix(summary, "# OAuch\n\n") {
			t.Fatalf("summary %q of %q has no heading", summary, export)
		}
	})
}
