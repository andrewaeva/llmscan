package watchlist

import "testing"

func TestAllLanguages(t *testing.T) {
	for _, l := range []string{"go", "python", "javascript", "typescript", "java"} {
		if got := All(l); len(got) == 0 {
			t.Errorf("All(%q) returned empty list", l)
		}
	}
	if got := All("cobol"); got != nil {
		t.Errorf("unknown lang should return nil, got %v", got)
	}
}

func TestHasHitGoSink(t *testing.T) {
	src := `package main
import "database/sql"
func h(db *sql.DB) { db.Exec("SELECT *") }`
	if !HasHit("go", src, KindSink) {
		t.Error("expected sink hit on db.Exec")
	}
}

func TestHasHitDefaultKinds(t *testing.T) {
	// When no kinds passed, defaults to source+sink.
	src := `eval(userInput)`
	if !HasHit("javascript", src) {
		t.Error("expected hit with default kinds")
	}
}

func TestHasHitMiss(t *testing.T) {
	src := `package main; func main() { println("hi") }`
	if HasHit("go", src, KindSink) {
		t.Error("clean code must not hit any sink")
	}
}

func TestHasHitCaseSensitive(t *testing.T) {
	// Watchlist matching is case-sensitive (cheaper than ToLower).
	if !HasHit("python", "cursor.execute('x')", KindSink) {
		t.Error("expected exact-case match for cursor.execute")
	}
	if HasHit("python", "Cursor.Execute('x')", KindSink) {
		t.Error("different case should not match (substring is case-sensitive)")
	}
}

func TestFindMatchesReturnsCategories(t *testing.T) {
	src := `req.query.id; child_process.exec(cmd);`
	got := FindMatches("javascript", src)
	if len(got) < 2 {
		t.Fatalf("expected at least 2 matches, got %+v", got)
	}
	cats := map[string]bool{}
	for _, e := range got {
		cats[e.Category] = true
	}
	if !cats["http"] || !cats["command"] {
		t.Errorf("expected categories http & command, got %v", cats)
	}
}

func TestFindMatchesKindFilter(t *testing.T) {
	src := `req.query.id; child_process.exec(cmd);`
	sinks := FindMatches("javascript", src, KindSink)
	for _, e := range sinks {
		if e.Kind != KindSink {
			t.Errorf("filter broken, got %v", e)
		}
	}
	if len(sinks) == 0 {
		t.Error("expected at least one sink")
	}
}

func BenchmarkHasHitGo(b *testing.B) {
	src := `package main
import ("database/sql"; "fmt")
func handler(db *sql.DB, id string) {
	q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	rows, _ := db.Exec(q)
	_ = rows
}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HasHit("go", src, KindSource, KindSink)
	}
}

func BenchmarkFindMatchesJS(b *testing.B) {
	src := `app.post('/u', (req, res) => {
		const cmd = req.query.cmd;
		child_process.exec(cmd);
		eval(req.body.code);
	});`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FindMatches("javascript", src)
	}
}
