package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Keyword is a BCP 14 requirement keyword.
type Keyword string

const (
	Must           Keyword = "MUST"
	MustNot        Keyword = "MUST NOT"
	Required       Keyword = "REQUIRED"
	Shall          Keyword = "SHALL"
	ShallNot       Keyword = "SHALL NOT"
	Should         Keyword = "SHOULD"
	ShouldNot      Keyword = "SHOULD NOT"
	Recommended    Keyword = "RECOMMENDED"
	NotRecommended Keyword = "NOT RECOMMENDED"
	May            Keyword = "MAY"
	Optional       Keyword = "OPTIONAL"
)

var keywords = []Keyword{Must, MustNot, Required, Shall, ShallNot, Should, ShouldNot, Recommended, NotRecommended, May, Optional}

// Absolute reports whether k states an absolute requirement or prohibition.
func (k Keyword) Absolute() bool {
	switch k {
	case Must, MustNot, Required, Shall, ShallNot:
		return true
	}
	return false
}

// Recommended reports whether k states a recommendation for or against.
func (k Keyword) Recommended() bool {
	switch k {
	case Should, ShouldNot, Recommended, NotRecommended:
		return true
	}
	return false
}

// Status is how a Requirement applies to this library.
type Status string

const (
	Applicable  Status = "applicable"
	Superseded  Status = "superseded"
	OutOfScope  Status = "out-of-scope"
	Informative Status = "informative"
	// Deviates is a recommended Requirement the library deliberately does not follow.
	Deviates Status = "deviates"
)

var statuses = []Status{Applicable, Superseded, OutOfScope, Informative, Deviates}

// Reason is why a Requirement is out-of-scope.
type Reason string

const (
	// ClientRequirement is a Requirement on a Client or an external Resource Server.
	ClientRequirement Reason = "client-requirement"
	// Excluded is a Requirement on a feature spec.md excludes.
	Excluded Reason = "excluded"
)

var reasons = []Reason{ClientRequirement, Excluded}

// excludedFile lists the features spec.md excludes.
const excludedFile = "excluded.yaml"

// gateFile says which Requirements the coverage gate checks besides absolute ones.
const gateFile = "gate.yaml"

// InvariantsDocument is the document ID of the Security Invariants.
const InvariantsDocument = "INV"

type Catalog struct {
	Documents []Document
	Excluded  []string
	// GateRecommended is whether the coverage gate checks recommended Requirements.
	GateRecommended bool
}

type excludedList struct {
	Features []string `yaml:"features"`
}

type gateFlags struct {
	Recommended bool `yaml:"recommended"`
}

type Document struct {
	ID           string        `yaml:"document"`
	Title        string        `yaml:"title"`
	Source       string        `yaml:"source,omitempty"`
	Requirements []Requirement `yaml:"requirements"`
}

type Requirement struct {
	ID           string   `yaml:"id"`
	Section      string   `yaml:"section,omitempty"`
	Keyword      Keyword  `yaml:"keyword"`
	Text         string   `yaml:"text"`
	Statement    string   `yaml:"statement,omitempty"`
	Status       Status   `yaml:"status"`
	Reason       Reason   `yaml:"reason,omitempty"`
	Feature      string   `yaml:"feature,omitempty"`
	SupersededBy []string `yaml:"superseded_by,omitempty"`
	Note         string   `yaml:"note,omitempty"`
}

var (
	documentID  = regexp.MustCompile(`^[A-Z][A-Z0-9]*$`)
	sectionID   = regexp.MustCompile(`^[0-9A-Z]+(\.[0-9]+)*$`)
	invariantID = regexp.MustCompile(`^INV-[0-9]{4}$`)
	featureName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	sequence    = regexp.MustCompile(`^[0-9]{2,}$`)
)

// Load reads the catalog in the root of fsys and validates it.
func Load(fsys fs.FS) (*Catalog, error) {
	c, err := read(fsys)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// read reads the excluded features, the gate flags and every other *.yaml document in the root of fsys.
func read(fsys fs.FS) (*Catalog, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var c Catalog
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".yaml" {
			continue
		}
		if e.Name() == excludedFile {
			l, err := decode[excludedList](fsys, e.Name())
			if err != nil {
				return nil, fmt.Errorf("%s: %w", e.Name(), err)
			}
			c.Excluded = l.Features
			continue
		}
		if e.Name() == gateFile {
			g, err := decode[gateFlags](fsys, e.Name())
			if err != nil {
				return nil, fmt.Errorf("%s: %w", e.Name(), err)
			}
			c.GateRecommended = g.Recommended
			continue
		}
		d, err := decode[Document](fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		c.Documents = append(c.Documents, d)
	}
	return &c, nil
}

// Validate reports every structural problem in the catalog.
func (c *Catalog) Validate() error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	features := map[string]bool{}
	for _, f := range c.Excluded {
		if !featureName.MatchString(f) {
			fail("excluded feature %q: invalid name", f)
		}
		if features[f] {
			fail("excluded feature %q: duplicate", f)
		}
		features[f] = true
	}

	docs := map[string]bool{}
	reqs := map[string]bool{}
	for _, d := range c.Documents {
		if !documentID.MatchString(d.ID) {
			fail("document %q: invalid document ID", d.ID)
		}
		if docs[d.ID] {
			fail("document %q: duplicate", d.ID)
		}
		docs[d.ID] = true
		if d.Title == "" {
			fail("document %q: missing title", d.ID)
		}
		if d.ID != InvariantsDocument && (d.Source == "" || path.IsAbs(d.Source)) {
			fail("document %q: source must be a relative path", d.ID)
		}

		for _, r := range d.Requirements {
			if !validID(d.ID, r) {
				fail("%s: ID does not match document %q and section %q", r.ID, d.ID, r.Section)
			}
			if reqs[r.ID] {
				fail("%s: duplicate", r.ID)
			}
			reqs[r.ID] = true
			if !slices.Contains(keywords, r.Keyword) {
				fail("%s: unknown keyword %q", r.ID, r.Keyword)
			}
			if !slices.Contains(statuses, r.Status) {
				fail("%s: unknown status %q", r.ID, r.Status)
			}
			if r.Text == "" {
				fail("%s: missing text", r.ID)
			}
			if r.Statement != "" && !slices.Contains(keywordsOf(strings.Join(strings.Fields(r.Statement), " ")), r.Keyword) {
				fail("%s: statement does not contain keyword %q", r.ID, r.Keyword)
			}
			if (r.Status == Superseded) != (len(r.SupersededBy) > 0) {
				fail("%s: superseded_by must be set exactly when status is %q", r.ID, Superseded)
			}
			if (r.Status == OutOfScope) != (r.Reason != "") {
				fail("%s: reason must be set exactly when status is %q", r.ID, OutOfScope)
			}
			if r.Status == Deviates && !r.Keyword.Recommended() {
				fail("%s: status %q needs a recommended keyword, not %q", r.ID, Deviates, r.Keyword)
			}
			if r.Status == Deviates && r.Note == "" {
				fail("%s: note must be set when status is %q", r.ID, Deviates)
			}
			if r.Reason != "" && !slices.Contains(reasons, r.Reason) {
				fail("%s: unknown reason %q", r.ID, r.Reason)
			}
			if (r.Reason == Excluded) != (r.Feature != "") {
				fail("%s: feature must be set exactly when reason is %q", r.ID, Excluded)
			}
			if r.Reason == Excluded && r.Feature != "" && !features[r.Feature] {
				fail("%s: feature %q is not in %s", r.ID, r.Feature, excludedFile)
			}
		}
	}

	for _, d := range c.Documents {
		texts := map[string]int{}
		for _, r := range d.Requirements {
			texts[r.Section+"\n"+r.Text]++
		}
		for _, r := range d.Requirements {
			if texts[r.Section+"\n"+r.Text] > 1 && r.Statement == "" {
				fail("%s: shares its text with another requirement and has no statement", r.ID)
			}
			for _, s := range r.SupersededBy {
				if s == r.ID || !reqs[s] {
					fail("%s: superseded_by %q is not another requirement in the catalog", r.ID, s)
				}
			}
		}
	}
	return errors.Join(errs...)
}

// decode reads a file that must hold exactly one YAML document.
func decode[T any](fsys fs.FS, name string) (T, error) {
	f, err := fsys.Open(name)
	if err != nil {
		var zero T
		return zero, err
	}
	defer func() { _ = f.Close() }()
	return parse[T](f)
}

// parse reads exactly one YAML document from r.
func parse[T any](r io.Reader) (T, error) {
	var v, zero T
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&v); errors.Is(err, io.EOF) {
		return zero, errors.New("empty file")
	} else if err != nil {
		return zero, err
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return zero, errors.New("more than one YAML document")
	}
	return v, nil
}

// validID checks that r.ID is "<document>-<section>-<NN>", or "INV-NNNN" for
// Security Invariants, which have no section.
func validID(doc string, r Requirement) bool {
	if doc == InvariantsDocument {
		return r.Section == "" && invariantID.MatchString(r.ID)
	}
	if !sectionID.MatchString(r.Section) {
		return false
	}
	n, ok := strings.CutPrefix(r.ID, doc+"-"+r.Section+"-")
	return ok && sequence.MatchString(n)
}
