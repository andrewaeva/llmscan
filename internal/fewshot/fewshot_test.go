package fewshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAndRetrieve(t *testing.T) {
	root := t.TempDir()
	// Skill 1: authz with two examples (one vuln, one safe).
	writeFile(t, filepath.Join(root, "authz", "SKILL.md"), "---\nname: authz\n---\n")
	writeFile(t, filepath.Join(root, "authz", "examples", "idor.json"), `{
		"title": "missing tenant filter",
		"verdict": "vuln",
		"language": "go",
		"code": "func GetOrder(c *gin.Context) { id := c.Param(\"id\"); db.First(&o, id) }",
		"rationale": "no tenant filter"
	}`)
	writeFile(t, filepath.Join(root, "authz", "examples", "safe.json"), `{
		"title": "scoped query",
		"verdict": "safe",
		"language": "go",
		"code": "func GetOrder(c *gin.Context) { id := c.Param(\"id\"); db.Where(\"tenant=?\", t).First(&o, id) }",
		"rationale": "scoped"
	}`)

	// Skill 2: injection (one array file).
	writeFile(t, filepath.Join(root, "injection", "examples", "many.json"), `[
		{"title":"sqli","verdict":"vuln","language":"go","code":"db.Exec(\"select * from t where id=\"+id)"},
		{"title":"prep","verdict":"safe","language":"go","code":"db.Exec(\"select * from t where id=?\", id)"}
	]`)

	b := New()
	if errs := b.LoadFromSkillDirs([]string{root}); len(errs) > 0 {
		t.Fatalf("load errs: %v", errs)
	}
	if got := b.Bank("authz"); got == nil || len(got.Examples) != 2 {
		t.Fatalf("authz bank wrong: %+v", got)
	}
	if got := b.Bank("injection"); got == nil || len(got.Examples) != 2 {
		t.Fatalf("injection bank wrong: %+v", got)
	}

	// Retrieval prefers the structurally closest example.
	query := "func GetOrder(c *gin.Context) { id := c.Param(\"id\"); db.First(&o, id) }"
	hits := b.Bank("authz").Retrieve(query, 2, "go")
	if len(hits) == 0 {
		t.Fatalf("no hits for clearly matching query")
	}
	if hits[0].Title != "missing tenant filter" {
		t.Errorf("expected top-1 IDOR example, got %q", hits[0].Title)
	}
}

func TestRetrieveLanguageFilter(t *testing.T) {
	b := &Bank{
		SkillName: "x",
		Examples: []Example{
			{Code: "a b c", Language: "go"},
			{Code: "a b c", Language: "python"},
		},
	}
	hits := b.Retrieve("a b c", 5, "python")
	if len(hits) != 1 || hits[0].Language != "python" {
		t.Errorf("expected python-only result, got %+v", hits)
	}
}

func TestRetrieveDropsZeroOverlap(t *testing.T) {
	b := &Bank{
		SkillName: "x",
		Examples: []Example{
			{Code: "alpha bravo charlie delta", Verdict: "vuln"},
		},
	}
	hits := b.Retrieve("zulu xray yankee whiskey", 3, "")
	if len(hits) != 0 {
		t.Errorf("zero overlap should yield no hits, got %+v", hits)
	}
}

func TestRenderPrompt(t *testing.T) {
	got := RenderPrompt([]Example{{
		Title:   "x",
		Verdict: "vuln",
		Code:    "do_bad()",
	}})
	if !strings.Contains(got, "VULN") || !strings.Contains(got, "do_bad()") {
		t.Errorf("bad render: %q", got)
	}
	if RenderPrompt(nil) != "" {
		t.Error("nil examples should render empty")
	}
}
