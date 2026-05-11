package skills

import (
	"path/filepath"
	"runtime"
	"testing"
)

// expected returns the set of skill names that must always be present.
func expected() []string {
	return []string{
		// existing
		"injection", "secrets", "auth", "crypto", "deserialization", "ssrf", "generic",
		"iac-docker", "iac-k8s", "iac-terraform", "iac-ghactions",
		// new (Trail of Bits / OWASP inspired)
		"insecure-defaults", "race-conditions", "error-handling", "supply-chain", "memory-safety",
	}
}

// repoSkillsDir resolves <repo-root>/skills regardless of cwd.
func repoSkillsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file = .../internal/skills/skills_test.go → go up two levels to repo root.
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "skills")
}

func TestLoadAllSkills(t *testing.T) {
	dir := repoSkillsDir(t)
	got, errs := LoadDir(dir)
	for _, err := range errs {
		t.Errorf("parse error: %v", err)
	}
	have := map[string]*Skill{}
	for _, s := range got {
		have[s.Name] = s
	}
	for _, name := range expected() {
		s, ok := have[name]
		if !ok {
			t.Errorf("missing skill %q under %s", name, dir)
			continue
		}
		if s.Prompt == "" {
			t.Errorf("skill %q has empty prompt body", name)
		}
		if s.Kind != "" && s.Kind != KindScanner {
			t.Errorf("skill %q has unexpected kind %q", name, s.Kind)
		}
	}
}
