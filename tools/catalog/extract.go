package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Candidate is one keyword occurrence in a sentence of a spec text.
type Candidate struct {
	Section string
	Keyword Keyword
	Text    string
}

const lineWidth = 72

var (
	heading     = regexp.MustCompile(`^(?:Appendix )?([0-9]+(?:\.[0-9]+)*|[A-Z](?:\.[0-9]+)*)\.  ?(\S.*)$`)
	changeLog   = regexp.MustCompile(`^(Document History|Change Log)$`)
	pageFooter  = regexp.MustCompile(`\[Page [0-9]+\]$`)
	pageHeader  = regexp.MustCompile(`^(RFC [0-9]+|Internet-Draft) {2,}`)
	listItem    = regexp.MustCompile(`^[o*-]  +`)
	sentenceEnd = regexp.MustCompile(`[^(][.!?]["')\]]*  `)
	keyword     = keywordPattern()

	requirementsKey = regexp.MustCompile(`(?m)^requirements:`)
)

// keywordPattern matches the keywords, preferring the longest at a position.
func keywordPattern() *regexp.Regexp {
	var alts []string
	for _, k := range keywords {
		alts = append(alts, string(k))
	}
	slices.SortStableFunc(alts, func(a, b string) int { return len(b) - len(a) })
	return regexp.MustCompile(`\b(` + strings.Join(alts, "|") + `)\b`)
}

// Extract returns a Candidate for every unquoted uppercase BCP 14 keyword in a numbered section.
func Extract(text string) []Candidate {
	var (
		out     []Candidate
		section string
		pieces  []string
		last    string
		list    bool
		open    bool
	)
	add := func(line string) {
		if list {
			line = strings.Join(strings.Fields(line), " ")
		}
		switch {
		case len(pieces) == 0:
		case hyphenated(last):
		case !list && endsSentence(last):
			pieces = append(pieces, "  ")
		default:
			pieces = append(pieces, " ")
		}
		pieces = append(pieces, line)
		last = line
	}
	flush := func() {
		if section != "" {
			for _, s := range sentences(strings.Join(pieces, "")) {
				for _, k := range keywordsOf(s) {
					out = append(out, Candidate{Section: section, Keyword: k, Text: s})
				}
			}
		}
		pieces, last, list, open = nil, "", false, false
	}

	for _, line := range pageLines(text) {
		if m := heading.FindStringSubmatch(line); m != nil {
			flush()
			section = m[1]
			if changeLog.MatchString(m[2]) {
				section = ""
			}
			continue
		}
		line = strings.TrimSpace(line)
		item := listItem.MatchString(line)
		line = listItem.ReplaceAllString(line, "")
		switch {
		case line == "" && len(pieces) > 0 && (list || strings.HasSuffix(last, ":") || !endsSentence(last)):
			open = true
		case line == "":
			flush()
		case open && item:
			list, open = true, false
			add(line)
		default:
			if open {
				flush()
			}
			add(line)
		}
	}
	flush()
	return out
}

// endsSentence reports whether s ends with a sentence end, which "(.)" is not.
func endsSentence(s string) bool {
	s = strings.TrimRight(s, `"')]`)
	return len(s) >= 2 && strings.ContainsRune(".!?", rune(s[len(s)-1])) && s[len(s)-2] != '('
}

// hyphenated reports whether s ends with a word broken by a hyphen.
func hyphenated(s string) bool {
	return len(s) >= 2 && s[len(s)-1] == '-' && s[len(s)-2] != ' '
}

// pageLines splits text into lines without page footers and headers.
func pageLines(text string) []string {
	text = strings.TrimPrefix(text, "\ufeff")
	var lines []string
	inBreak := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, " \r")
		switch {
		case pageFooter.MatchString(line):
			for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
				lines = lines[:len(lines)-1]
			}
			inBreak = true
			continue
		case inBreak && (strings.Trim(line, "\f ") == "" || pageHeader.MatchString(strings.TrimLeft(line, "\f"))):
			continue
		case inBreak && !continues(lines, line):
			lines = append(lines, "")
		}
		inBreak = false
		lines = append(lines, line)
	}
	return lines
}

// continues reports whether line continues the last line, which was wrapped mid-sentence.
func continues(lines []string, line string) bool {
	if len(lines) == 0 {
		return false
	}
	prev := lines[len(lines)-1]
	first := len(lines) == 1 || strings.TrimSpace(lines[len(lines)-2]) == ""
	trimmed := strings.TrimSpace(prev)
	word, _, _ := strings.Cut(strings.TrimSpace(line), " ")
	return (indent(line) == indent(prev) || first && indent(line) > indent(prev)) &&
		len(prev)+1+len(word) > lineWidth && !endsSentence(trimmed) && !strings.HasSuffix(trimmed, ":")
}

func indent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// sentences splits a paragraph at sentence ends, which are followed by two spaces.
func sentences(paragraph string) []string {
	var out []string
	for paragraph != "" {
		end := len(paragraph)
		if loc := sentenceEnd.FindStringIndex(paragraph); loc != nil {
			end = loc[1] - 2
		}
		out = append(out, strings.Join(strings.Fields(paragraph[:end]), " "))
		paragraph = strings.TrimSpace(paragraph[end:])
	}
	return out
}

// keywordsOf returns the keywords in s that are not quoted mentions.
func keywordsOf(s string) []Keyword {
	var out []Keyword
	for _, m := range keyword.FindAllStringIndex(s, -1) {
		if m[0] > 0 && m[1] < len(s) && s[m[0]-1] == '"' && s[m[1]] == '"' {
			continue
		}
		out = append(out, Keyword(s[m[0]:m[1]]))
	}
	return out
}

// extractFile appends the new candidates of a catalog file's source to it.
func extractFile(name string, stdout io.Writer) error {
	data, err := os.ReadFile(name) // #nosec G304 G703 -- the maintainer names the catalog file
	if err != nil {
		return err
	}
	d, err := parse(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	text, err := os.ReadFile(filepath.Join(filepath.Dir(name), d.Source)) // #nosec G304 G703 -- the source is a relative path in the catalog
	if err != nil {
		return err
	}

	added, report := merge(d, Extract(string(text)))
	if len(added) > 0 {
		data, err = appendRequirements(data, d, added)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := os.WriteFile(name, data, 0o600); err != nil { // #nosec G703 -- the maintainer names the catalog file
			return err
		}
	}
	_, err = io.WriteString(stdout, strings.Join(report, ""))
	return err
}

// appendRequirements appends rs to the requirements list at the end of data.
func appendRequirements(data []byte, d Document, rs []Requirement) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(Document{Requirements: rs}); err != nil {
		return nil, err
	}
	_, items, _ := strings.Cut(buf.String(), "requirements:\n")

	out := bytes.TrimRight(data, "\n")
	if len(d.Requirements) == 0 && !requirementsKey.Match(data) {
		out = append(out, "\nrequirements:"...)
	}
	out = append(append(out, '\n'), items...)

	got, err := parse(bytes.NewReader(out))
	if err != nil || !reflect.DeepEqual(got.Requirements, append(d.Requirements, rs...)) {
		return nil, errors.New("cannot append; the requirements block list must come last")
	}
	return out, nil
}

// quote is the text of a sentence in a section.
type quote struct{ section, text string }

// merge returns the candidates no Requirement of d quotes, and report lines on new, changed and removed sentences.
func merge(d Document, candidates []Candidate) ([]Requirement, []string) {
	extracted := map[quote]bool{}
	for _, c := range candidates {
		extracted[quote{c.Section, c.Text}] = true
	}

	ids := map[quote][]string{}
	used := map[string]bool{}
	var unmatched []quote
	for _, r := range d.Requirements {
		q := quote{r.Section, r.Text}
		if ids[q] == nil && !extracted[q] {
			unmatched = append(unmatched, q)
		}
		ids[q] = append(ids[q], r.ID)
		used[r.ID] = true
	}

	var (
		added  []Requirement
		report []string
	)
	isNew := map[quote]bool{}
	for _, c := range candidates {
		q := quote{c.Section, c.Text}
		if !isNew[q] {
			if ids[q] != nil {
				continue
			}
			if i := mostSimilar(unmatched, q); i >= 0 {
				ids[q] = ids[unmatched[i]]
				report = append(report, fmt.Sprintf("changed %s: %s\n", strings.Join(ids[q], ", "), q.text))
				unmatched = slices.Delete(unmatched, i, i+1)
				continue
			}
			isNew[q] = true
		}
		r := Requirement{ID: freeID(d.ID, c.Section, used), Section: c.Section, Keyword: c.Keyword, Text: c.Text}
		used[r.ID] = true
		added = append(added, r)
		report = append(report, fmt.Sprintf("new %s: %s\n", r.ID, r.Text))
	}
	for _, u := range unmatched {
		report = append(report, fmt.Sprintf("removed %s: %s\n", strings.Join(ids[u], ", "), u.text))
	}
	return added, report
}

// freeID returns the ID with the lowest sequence number not yet used in section.
func freeID(doc, section string, used map[string]bool) string {
	for n := 1; ; n++ {
		if id := fmt.Sprintf("%s-%s-%02d", doc, section, n); !used[id] {
			return id
		}
	}
}

// mostSimilar returns the index of the quote in q's section most similar to q, if at least half alike, or -1.
func mostSimilar(quotes []quote, q quote) int {
	best, bestScore := -1, 0.0
	for i, u := range quotes {
		if score := similarity(u.text, q.text); u.section == q.section && score >= 0.5 && score > bestScore {
			best, bestScore = i, score
		}
	}
	return best
}

// similarity returns the Jaccard index of the words of a and b.
func similarity(a, b string) float64 {
	wa, wb := map[string]bool{}, map[string]bool{}
	for _, w := range strings.Fields(a) {
		wa[w] = true
	}
	for _, w := range strings.Fields(b) {
		wb[w] = true
	}
	common := 0
	for w := range wa {
		if wb[w] {
			common++
		}
	}
	return float64(common) / float64(len(wa)+len(wb)-common)
}
