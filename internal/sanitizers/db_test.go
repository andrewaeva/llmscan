package sanitizers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultEmbedded(t *testing.T) {
	db, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	if db == nil || len(db.All()) < 30 {
		t.Fatalf("expected >=30 default rules, got %d", len(db.All()))
	}
	langs := db.Languages()
	for _, want := range []string{"java", "python", "javascript", "typescript", "go"} {
		found := false
		for _, l := range langs {
			if l == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("language %q missing from default DB; got %v", want, langs)
		}
	}
}

func TestMatchPerLangAndCategory(t *testing.T) {
	db := MustLoadDefault()
	// Java PreparedStatement setString -> sql
	hits := db.Match("java", `ps.setString(1, userInput);`, []string{"sql"})
	if len(hits) == 0 {
		t.Fatalf("expected java setString match for sql, got nothing")
	}
	// Same line for xss must NOT match the SQL-only rule.
	hits = db.Match("java", `ps.setString(1, userInput);`, []string{"xss"})
	for _, h := range hits {
		if h.ID == "java-prepared-statement-setstring" {
			t.Errorf("PreparedStatement should not match xss category")
		}
	}
	// Python html.escape -> xss
	hits = db.Match("python", `safe = html.escape(name)`, []string{"xss"})
	if len(hits) == 0 {
		t.Fatalf("html.escape should match xss")
	}
	// Go filepath.Clean -> path
	hits = db.Match("go", `p := filepath.Clean(userPath)`, []string{"path"})
	if len(hits) == 0 {
		t.Fatalf("filepath.Clean should match path")
	}
	// JS encodeURIComponent -> ssrf
	hits = db.Match("javascript", `const u = encodeURIComponent(raw)`, []string{"ssrf"})
	if len(hits) == 0 {
		t.Fatalf("encodeURIComponent should match ssrf")
	}
}

func TestMatchCallee(t *testing.T) {
	db := MustLoadDefault()
	if got := db.MatchCallee("java", "ps.setString"); len(got) == 0 {
		t.Fatalf("MatchCallee setString failed")
	}
	if got := db.MatchCallee("python", "escape"); len(got) == 0 {
		t.Fatalf("MatchCallee escape failed")
	}
	if got := db.MatchCallee("javascript", "validator.isEmail"); len(got) != 0 {
		// not in CalleeNames; only patterns — must be empty
		t.Errorf("validator.isEmail should not match by callee name (only by pattern)")
	}
}

func TestNoFalseMatchOnArbitraryLine(t *testing.T) {
	db := MustLoadDefault()
	cases := []struct{ lang, line string }{
		{"go", `fmt.Println("hello")`},
		{"java", `int x = 1 + 2;`},
		{"python", `total = total + 1`},
		{"javascript", `const x = 42;`},
	}
	for _, c := range cases {
		if got := db.Match(c.lang, c.line, nil); len(got) > 0 {
			t.Errorf("unexpected matches for %s line %q: %+v", c.lang, c.line, got[0].ID)
		}
	}
}

func TestNegativeAntiPattern(t *testing.T) {
	db := MustLoadDefault()
	hits := db.Match("python", `html = mark_safe(user_input)`, []string{"xss"})
	found := false
	for _, h := range hits {
		if h.Negative {
			found = true
		}
	}
	if !found {
		t.Errorf("mark_safe must be flagged as negative anti-pattern, got %+v", hits)
	}
}

func TestLoadFromFile(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "extra.yaml")
	content := `- id: custom-foo
  name: Custom
  languages: [go]
  categories: [sql]
  patterns:
    - '\bcustomSanitize\b'
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	hits := db.Match("go", `customSanitize(x)`, []string{"sql"})
	if len(hits) != 1 || hits[0].ID != "custom-foo" {
		t.Errorf("custom rule not loaded: %+v", hits)
	}
}

func TestEmbedNonEmpty(t *testing.T) {
	if !strings.Contains(string(embeddedYAML), "java-prepared-statement-setstring") {
		t.Fatal("embedded YAML missing expected rule")
	}
}
