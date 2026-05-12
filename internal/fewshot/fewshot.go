// Package fewshot loads per-skill banks of vulnerable / non-vulnerable code
// examples and retrieves the most relevant ones for a given scanner chunk.
//
// The retrieval is intentionally lightweight: no embedding model is required.
// Scoring is a token-overlap heuristic (Jaccard on shingle sets) which is
// cheap, deterministic, and good enough to pick out a handful of structurally
// similar examples from a bank of 20-200. When higher-quality retrieval is
// needed later, a host can plug in a rag.Embedder; this package exposes a
// SetEmbedder hook for that purpose but otherwise stays embedder-free.
//
// File layout on disk:
//
//	skills/<name>/SKILL.md
//	skills/<name>/examples/*.json   # one Example per file (or an array)
//
// Each example is a small JSON object:
//
//	{
//	  "title":      "missing tenant check on GET /orders/:id",
//	  "verdict":    "vuln",                       // "vuln" | "safe"
//	  "language":   "go",                         // optional
//	  "code":       "func Get(...) {...}",
//	  "rationale":  "no WHERE tenant_id filter; IDOR",
//	  "fix":        "scope query to ctx tenant"   // optional
//	}
package fewshot

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Example is one annotated code snippet used as in-context demonstration.
type Example struct {
	Title     string `json:"title"`
	Verdict   string `json:"verdict"` // "vuln" or "safe"
	Language  string `json:"language,omitempty"`
	Code      string `json:"code"`
	Rationale string `json:"rationale,omitempty"`
	Fix       string `json:"fix,omitempty"`

	// Provenance set by the loader.
	SkillName string `json:"-"`
	Path      string `json:"-"`
}

// Bank holds the examples for one skill and provides Retrieve.
type Bank struct {
	SkillName string
	Examples  []Example
}

// Banks is a mapping from skill name to its Bank. Loading is per skill so
// callers can pass it to per-scanner code paths without scanning the disk on
// every chunk.
type Banks struct {
	mu    sync.RWMutex
	byKey map[string]*Bank
}

// New returns an empty Banks registry.
func New() *Banks { return &Banks{byKey: map[string]*Bank{}} }

// LoadFromSkillDirs walks every skill directory looking for
// `<skill>/examples/*.json` and registers a Bank per skill that has at least
// one example. Files that fail to parse are reported in the returned errors
// slice but never abort loading.
func (b *Banks) LoadFromSkillDirs(dirs []string) []error {
	var errs []error
	for _, root := range dirs {
		// Each immediate subdir of `root` is a skill folder.
		entries, err := os.ReadDir(root)
		if err != nil {
			// Missing skill dir is not fatal; skip silently.
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
				continue
			}
			skillName := e.Name()
			examplesDir := filepath.Join(root, skillName, "examples")
			if st, err := os.Stat(examplesDir); err != nil || !st.IsDir() {
				continue
			}
			es, lerrs := loadExampleDir(examplesDir, skillName)
			errs = append(errs, lerrs...)
			if len(es) == 0 {
				continue
			}
			b.mu.Lock()
			if existing, ok := b.byKey[skillName]; ok {
				existing.Examples = append(existing.Examples, es...)
			} else {
				b.byKey[skillName] = &Bank{SkillName: skillName, Examples: es}
			}
			b.mu.Unlock()
		}
	}
	return errs
}

// Bank returns the registered bank for the given skill, or nil when none.
func (b *Banks) Bank(skill string) *Bank {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.byKey[skill]
}

// SkillNames returns the names of every loaded bank, sorted.
func (b *Banks) SkillNames() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	names := make([]string, 0, len(b.byKey))
	for k := range b.byKey {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Retrieve returns the top-k examples whose code is most similar to `query`.
// Similarity is a 3-gram Jaccard score on lowercased identifier shingles —
// fast, language-agnostic, and surprisingly robust for short code chunks.
func (k *Bank) Retrieve(query string, top int, languageHint string) []Example {
	if k == nil || len(k.Examples) == 0 || top <= 0 {
		return nil
	}
	qset := shingleSet(query)
	type scored struct {
		e Example
		s float64
	}
	cands := make([]scored, 0, len(k.Examples))
	for _, e := range k.Examples {
		if languageHint != "" && e.Language != "" &&
			!strings.EqualFold(languageHint, e.Language) {
			continue
		}
		s := jaccard(qset, shingleSet(e.Code))
		cands = append(cands, scored{e, s})
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].s > cands[j].s })
	if top > len(cands) {
		top = len(cands)
	}
	out := make([]Example, 0, top)
	for i := 0; i < top; i++ {
		// Drop zero-overlap candidates so the prompt isn't padded with noise.
		if cands[i].s == 0 {
			break
		}
		out = append(out, cands[i].e)
	}
	return out
}

// RenderPrompt produces a compact markdown block ready to append to a system
// prompt. Returns "" when es is empty so callers can do `prompt += block`
// unconditionally.
func RenderPrompt(es []Example) string {
	if len(es) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n## In-context examples\n")
	b.WriteString("Use these annotated snippets as calibration. Match on STRUCTURE, not surface tokens.\n")
	for i, e := range es {
		fmt.Fprintf(&b, "\n### Example %d — verdict: %s\n", i+1, strings.ToUpper(e.Verdict))
		if e.Title != "" {
			fmt.Fprintf(&b, "Title: %s\n", e.Title)
		}
		lang := e.Language
		if lang == "" {
			lang = ""
		}
		fmt.Fprintf(&b, "```%s\n%s\n```\n", lang, strings.TrimSpace(e.Code))
		if e.Rationale != "" {
			fmt.Fprintf(&b, "Rationale: %s\n", oneLine(e.Rationale))
		}
		if e.Fix != "" {
			fmt.Fprintf(&b, "Fix: %s\n", oneLine(e.Fix))
		}
	}
	return b.String()
}

// ---- loader ----

func loadExampleDir(dir, skill string) ([]Example, []error) {
	var (
		out  []Example
		errs []error
	)
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(p), ".json") {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, rerr))
			return nil
		}
		// Accept either a single object or an array of objects.
		trimmed := strings.TrimSpace(string(raw))
		if strings.HasPrefix(trimmed, "[") {
			var arr []Example
			if jerr := json.Unmarshal(raw, &arr); jerr != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p, jerr))
				return nil
			}
			for i := range arr {
				if arr[i].Code == "" {
					continue
				}
				arr[i].SkillName = skill
				arr[i].Path = p
				out = append(out, arr[i])
			}
			return nil
		}
		var one Example
		if jerr := json.Unmarshal(raw, &one); jerr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, jerr))
			return nil
		}
		if one.Code == "" {
			return nil
		}
		one.SkillName = skill
		one.Path = p
		out = append(out, one)
		return nil
	})
	return out, errs
}

// ---- scoring ----

// shingleSet builds a set of normalized 3-grams from identifier-like tokens.
// Punctuation is collapsed; case is ignored.
func shingleSet(text string) map[string]struct{} {
	out := make(map[string]struct{}, 64)
	low := strings.ToLower(text)
	// Replace non-identifier chars with space.
	var b strings.Builder
	b.Grow(len(low))
	for _, c := range low {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte(' ')
		}
	}
	for _, tok := range strings.Fields(b.String()) {
		if len(tok) < 3 {
			out[tok] = struct{}{}
			continue
		}
		// 3-gram shingles per token.
		for i := 0; i+3 <= len(tok); i++ {
			out[tok[i:i+3]] = struct{}{}
		}
	}
	return out
}

func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	small, big := a, b
	if len(b) < len(a) {
		small, big = b, a
	}
	for k := range small {
		if _, ok := big[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 240 {
		s = s[:240] + "..."
	}
	return s
}
