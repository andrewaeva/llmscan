// Package skills loads scanner definitions from SKILL.md files with YAML frontmatter.
//
// Each skill describes ONE specialized scanner agent: its name, the layer it
// belongs to in the DAG, its dependencies, languages it cares about and the
// raw system prompt the agent should use. This is the same convention used by
// Anthropic Agent Skills / Claude Code.
package skills

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SkillKind classifies what kind of agent a skill defines.
type SkillKind string

const (
	KindScanner       SkillKind = "scanner"
	KindOrchestrator  SkillKind = "orchestrator"
	KindContextFilter SkillKind = "context_filter"
	KindVerifier      SkillKind = "verifier"
	KindFPFilter      SkillKind = "fp_filter"
)

// Skill is one parsed SKILL.md file.
type Skill struct {
	// frontmatter
	Name        string    `yaml:"name"`
	Kind        SkillKind `yaml:"kind"` // scanner | orchestrator | ...
	Description string    `yaml:"description"`
	Layer       int       `yaml:"layer,omitempty"` // hint for DAG layering (lower = earlier)
	DependsOn   []string  `yaml:"depends_on,omitempty"`
	Languages   []string  `yaml:"languages,omitempty"` // empty = any
	CWE         []string  `yaml:"cwe,omitempty"`
	Severity    string    `yaml:"severity,omitempty"`
	Enabled     *bool     `yaml:"enabled,omitempty"`

	// body
	Prompt string `yaml:"-"` // markdown body after frontmatter

	// metadata
	Path string `yaml:"-"`
}

// IsEnabled returns Enabled if explicitly set, otherwise true.
func (s *Skill) IsEnabled() bool {
	if s.Enabled == nil {
		return true
	}
	return *s.Enabled
}

// LoadDir loads every SKILL.md found under root (recursive). Files that fail
// to parse are reported with their path; loading continues for the rest.
func LoadDir(root string) ([]*Skill, []error) {
	var skills []*Skill
	var errs []error
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Base(p), "SKILL.md") {
			return nil
		}
		s, e := LoadFile(p)
		if e != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, e))
			return nil
		}
		skills = append(skills, s)
		return nil
	})
	return skills, errs
}

// LoadFile parses one SKILL.md file.
func LoadFile(path string) (*Skill, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fm, body, err := splitFrontmatter(raw)
	if err != nil {
		return nil, err
	}
	var s Skill
	if err := yaml.Unmarshal(fm, &s); err != nil {
		return nil, fmt.Errorf("frontmatter yaml: %w", err)
	}
	if s.Name == "" {
		return nil, fmt.Errorf("skill name is required")
	}
	if s.Kind == "" {
		s.Kind = KindScanner
	}
	s.Prompt = strings.TrimSpace(string(body))
	s.Path = path
	return &s, nil
}

// splitFrontmatter expects a YAML block delimited by --- at the very top.
func splitFrontmatter(raw []byte) ([]byte, []byte, error) {
	s := string(raw)
	s = strings.TrimLeft(s, "\ufeff") // strip BOM
	if !strings.HasPrefix(s, "---") {
		return nil, nil, fmt.Errorf("missing --- frontmatter")
	}
	rest := strings.TrimPrefix(s, "---")
	rest = strings.TrimLeft(rest, "\r\n")
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return nil, nil, fmt.Errorf("unterminated frontmatter")
	}
	fm := rest[:end]
	body := rest[end+len("\n---"):]
	body = strings.TrimLeft(body, "\r\n")
	return []byte(fm), []byte(body), nil
}
