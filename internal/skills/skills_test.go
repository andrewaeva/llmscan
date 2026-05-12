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
		"injection", "auth", "crypto", "deserialization", "ssrf", "generic",
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

func TestLoadDirSkipsUnderscoreDirs(t *testing.T) {
	dir := repoSkillsDir(t)
	got, _ := LoadDir(dir)
	for _, s := range got {
		if filepath.Base(filepath.Dir(s.Path))[0] == '_' {
			t.Errorf("LoadDir surfaced a special skill %q from %s", s.Name, s.Path)
		}
	}
}

func TestLoadSpecialFPCheckVerifier(t *testing.T) {
	dir := repoSkillsDir(t)
	sk, err := LoadSpecial(dir, "_fpcheck-verifier")
	if err != nil {
		t.Fatalf("LoadSpecial: %v", err)
	}
	if sk == nil {
		t.Fatal("expected the _fpcheck-verifier skill to load")
	}
	if sk.Kind != "verifier" {
		t.Errorf("kind=%q, want verifier", sk.Kind)
	}
	if sk.Prompt == "" {
		t.Error("body must not be empty")
	}
}

func TestLoadSpecialFPCheckDeep(t *testing.T) {
	dir := repoSkillsDir(t)
	sk, err := LoadSpecial(dir, "_fpcheck-deep")
	if err != nil {
		t.Fatalf("LoadSpecial: %v", err)
	}
	if sk == nil {
		t.Fatal("expected the _fpcheck-deep skill to load")
	}
	if sk.Kind != "deep" {
		t.Errorf("kind=%q, want deep", sk.Kind)
	}
}

func TestLoadSpecialRejectsNonUnderscore(t *testing.T) {
	if _, err := LoadSpecial(".", "injection"); err == nil {
		t.Error("expected error for non-underscore dir name")
	}
}

func TestLoadSpecialMissing(t *testing.T) {
	sk, err := LoadSpecial(t.TempDir(), "_does-not-exist")
	if err != nil {
		t.Errorf("missing skill should not error: %v", err)
	}
	if sk != nil {
		t.Errorf("missing skill should return nil, got %+v", sk)
	}
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
