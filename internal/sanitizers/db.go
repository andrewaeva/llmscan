// Package sanitizers implements a framework-aware database of input
// validators and output encoders ("sanitizers") used by the taint analyzer
// to suppress false positives.
//
// A Sanitizer entry describes one or more textual patterns (Go regexp
// syntax) that, when matched on a source line, indicate the data passing
// through that line is no longer attacker-controlled for the listed
// categories (sql, xss, command, path, ...).
//
// The default rule set ships embedded as sanitizers.yaml and covers Java
// (Spring/ESAPI/OWASP/Bean Validation/PreparedStatement), Python
// (Django ORM, html.escape, bleach, shlex.quote, secure_filename, ...),
// JavaScript / TypeScript (validator.js, DOMPurify, sequelize/prisma
// parametrized queries, lodash.escape, encodeURIComponent, xss),
// and Go (html/template, html.EscapeString, sql.DB.Query with
// placeholders, regexp.QuoteMeta, filepath.Clean, url.QueryEscape,
// bluemonday).
//
// All rules are tagged with OWASP / Snyk / CWE references so downstream
// reporters can surface the rationale.
package sanitizers

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Sanitizer is one record in the database.
type Sanitizer struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Languages   []string `yaml:"languages"`
	Categories  []string `yaml:"categories"`
	Framework   string   `yaml:"framework,omitempty"`
	Patterns    []string `yaml:"patterns"`
	CalleeNames []string `yaml:"callee_names,omitempty"`
	Notes       string   `yaml:"notes,omitempty"`
	References  []string `yaml:"references,omitempty"`
	// Negative marks the rule as an anti-pattern (e.g. Django mark_safe):
	// matching it does NOT clear taint; reporters may surface a warning.
	Negative bool `yaml:"negative,omitempty"`

	// compiled regexes for Patterns; populated lazily by compile().
	compiled []*regexp.Regexp
}

// DB is an indexed in-memory database of sanitizer rules.
type DB struct {
	items   []Sanitizer
	perLang map[string][]*Sanitizer
	perCat  map[string][]*Sanitizer
	mu      sync.Mutex
}

//go:embed sanitizers.yaml
var embeddedYAML []byte

var (
	defaultDB     *DB
	defaultDBErr  error
	defaultDBOnce sync.Once
)

// Load parses one or more YAML files (each may contain a single list of
// Sanitizer entries OR multiple `---` separated documents) and returns
// a fully indexed DB. Unknown / malformed entries are silently dropped.
func Load(paths ...string) (*DB, error) {
	db := &DB{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("sanitizers: read %s: %w", p, err)
		}
		if err := db.appendYAML(b); err != nil {
			return nil, fmt.Errorf("sanitizers: parse %s: %w", p, err)
		}
	}
	db.index()
	return db, nil
}

// LoadDefault loads the embedded default rule set. The result is cached.
func LoadDefault() (*DB, error) {
	defaultDBOnce.Do(func() {
		db := &DB{}
		if err := db.appendYAML(embeddedYAML); err != nil {
			defaultDBErr = err
			return
		}
		db.index()
		defaultDB = db
	})
	return defaultDB, defaultDBErr
}

// MustLoadDefault is a convenience for callers that want the embedded
// database without dealing with the (extremely unlikely) parse error.
// It panics on failure; production code should prefer LoadDefault.
func MustLoadDefault() *DB {
	db, err := LoadDefault()
	if err != nil {
		panic(err)
	}
	return db
}

// All returns all sanitizer entries (read-only).
func (db *DB) All() []Sanitizer {
	if db == nil {
		return nil
	}
	out := make([]Sanitizer, len(db.items))
	copy(out, db.items)
	return out
}

// Match returns sanitizers whose Patterns match the given line for the
// requested language. When cats is non-empty, only sanitizers covering at
// least one of the requested categories are returned. Negative
// (anti-pattern) entries are also returned so callers can decide what to
// do — check the Negative field.
func (db *DB) Match(lang, line string, cats []string) []*Sanitizer {
	if db == nil || line == "" {
		return nil
	}
	var out []*Sanitizer
	wantCat := map[string]bool{}
	for _, c := range cats {
		wantCat[strings.ToLower(c)] = true
	}
	seen := map[string]bool{}
	for _, s := range db.perLang[strings.ToLower(lang)] {
		if len(wantCat) > 0 && !anyMatch(s.Categories, wantCat) {
			continue
		}
		if seen[s.ID] {
			continue
		}
		for _, re := range s.compiled {
			if re.MatchString(line) {
				out = append(out, s)
				seen[s.ID] = true
				break
			}
		}
	}
	return out
}

// MatchCallee returns sanitizers whose CalleeNames include name (exact or
// suffix match after dot — e.g. "setString" matches "ps.setString").
func (db *DB) MatchCallee(lang, name string) []*Sanitizer {
	if db == nil || name == "" {
		return nil
	}
	n := strings.TrimSpace(name)
	short := n
	if dot := strings.LastIndex(n, "."); dot >= 0 {
		short = n[dot+1:]
	}
	var out []*Sanitizer
	seen := map[string]bool{}
	for _, s := range db.perLang[strings.ToLower(lang)] {
		for _, c := range s.CalleeNames {
			if c == n || c == short {
				if seen[s.ID] {
					break
				}
				out = append(out, s)
				seen[s.ID] = true
				break
			}
		}
	}
	return out
}

// PerCategory returns the sanitizers (across all languages) tagged with cat.
func (db *DB) PerCategory(cat string) []*Sanitizer {
	if db == nil {
		return nil
	}
	return db.perCat[strings.ToLower(cat)]
}

// Languages returns the set of language identifiers known to the database.
func (db *DB) Languages() []string {
	if db == nil {
		return nil
	}
	out := make([]string, 0, len(db.perLang))
	for l := range db.perLang {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

func (db *DB) appendYAML(b []byte) error {
	// Two accepted shapes: a single list-of-sanitizers, or multiple YAML
	// documents each containing one such list. yaml.v3 Decoder handles
	// both cleanly via repeated Decode().
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	for {
		var doc []Sanitizer
		if err := dec.Decode(&doc); err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			return err
		}
		for _, s := range doc {
			if s.ID == "" || len(s.Patterns) == 0 {
				continue
			}
			db.items = append(db.items, s)
		}
	}
}

func (db *DB) index() {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.perLang = map[string][]*Sanitizer{}
	db.perCat = map[string][]*Sanitizer{}
	for i := range db.items {
		s := &db.items[i]
		s.compiled = s.compiled[:0]
		for _, p := range s.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				continue
			}
			s.compiled = append(s.compiled, re)
		}
		for _, l := range s.Languages {
			lk := strings.ToLower(l)
			db.perLang[lk] = append(db.perLang[lk], s)
		}
		for _, c := range s.Categories {
			ck := strings.ToLower(c)
			db.perCat[ck] = append(db.perCat[ck], s)
		}
	}
}

func anyMatch(have []string, want map[string]bool) bool {
	for _, h := range have {
		if want[strings.ToLower(h)] {
			return true
		}
	}
	return false
}
