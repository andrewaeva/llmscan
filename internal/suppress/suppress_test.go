package suppress

import "testing"

func TestParseGoStyle(t *testing.T) {
	src := `package main

// llmscan:ignore[sql-injection] reason: prepared statement upstream
func A() {}

// llmscan:ignore[*] reason: legacy module
func B() {}
`
	ss := Parse("a.go", src)
	if len(ss) != 2 {
		t.Fatalf("expected 2 markers, got %d: %+v", len(ss), ss)
	}
	if ss[0].Rule != "sql-injection" || ss[0].Reason != "prepared statement upstream" {
		t.Errorf("unexpected first marker: %+v", ss[0])
	}
	if ss[1].Rule != "*" {
		t.Errorf("expected wildcard, got %q", ss[1].Rule)
	}
}

func TestParsePythonStyle(t *testing.T) {
	src := "password = 'x'  # llmscan:ignore[generic-password] reason: test fixture\n"
	ss := Parse("t.py", src)
	if len(ss) != 1 || ss[0].Rule != "generic-password" {
		t.Fatalf("unexpected: %+v", ss)
	}
	if ss[0].Reason != "test fixture" {
		t.Errorf("reason = %q", ss[0].Reason)
	}
}

func TestParseBlockComment(t *testing.T) {
	src := "/* llmscan:ignore[xss] reason: encoded later */\nfoo()\n"
	ss := Parse("a.go", src)
	if len(ss) != 1 || ss[0].Rule != "xss" {
		t.Fatalf("unexpected: %+v", ss)
	}
}

func TestMatchAtSameLine(t *testing.T) {
	ss := []Suppression{{File: "a.go", Line: 10, Rule: "sql"}}
	if _, ok := MatchAt(ss, "a.go", 10, "sql", "scan:injection"); !ok {
		t.Error("expected match on same line")
	}
}

func TestMatchAtLineBelow(t *testing.T) {
	ss := []Suppression{{File: "a.go", Line: 10, Rule: "sql"}}
	if _, ok := MatchAt(ss, "a.go", 11, "sql", "scan:injection"); !ok {
		t.Error("expected match on line+1 (marker placed above finding)")
	}
	if _, ok := MatchAt(ss, "a.go", 12, "sql", "scan:injection"); ok {
		t.Error("must not match two lines below")
	}
}

func TestMatchAtWildcard(t *testing.T) {
	ss := []Suppression{{File: "a.go", Line: 5, Rule: "*"}}
	if _, ok := MatchAt(ss, "a.go", 5, "anything", "any-agent"); !ok {
		t.Error("wildcard must match any rule")
	}
}

func TestMatchAtAgent(t *testing.T) {
	ss := []Suppression{{File: "a.go", Line: 5, Rule: "scan:injection"}}
	if _, ok := MatchAt(ss, "a.go", 5, "sql-rule", "scan:injection"); !ok {
		t.Error("must match by agent name")
	}
}

func TestMatchAtDifferentFile(t *testing.T) {
	ss := []Suppression{{File: "a.go", Line: 5, Rule: "*"}}
	if _, ok := MatchAt(ss, "b.go", 5, "x", "y"); ok {
		t.Error("must not match different file")
	}
}

func BenchmarkParse(b *testing.B) {
	src := ""
	for i := 0; i < 500; i++ {
		src += "func x() {} // some line\n"
	}
	src += "// llmscan:ignore[sql] reason: parameterized\n"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Parse("a.go", src)
	}
}
