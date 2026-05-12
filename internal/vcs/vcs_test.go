package vcs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectGit(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	v, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if v.Kind() != KindGit {
		t.Errorf("Kind=%s, want git", v.Kind())
	}
	if v.Root() != dir {
		t.Errorf("Root=%s, want %s", v.Root(), dir)
	}
}

func TestDetectArc(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".arc"), 0o755); err != nil {
		t.Fatal(err)
	}
	v, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if v.Kind() != KindArc {
		t.Errorf("Kind=%s, want arc", v.Kind())
	}
}

func TestDetectNone(t *testing.T) {
	dir := t.TempDir()
	v, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if v.Kind() != KindNone {
		t.Errorf("Kind=%s, want none", v.Kind())
	}
}

func TestDetectWalksUp(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	v, err := Detect(sub)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if v.Kind() != KindGit {
		t.Errorf("Kind=%s, want git from nested dir", v.Kind())
	}
	if v.Root() != dir {
		t.Errorf("Root=%s, want %s", v.Root(), dir)
	}
}

func TestParseRange(t *testing.T) {
	cases := []struct {
		in       string
		wantSpec string
		wantKind Kind
	}{
		{"", "", KindNone},
		{"origin/main..HEAD", "origin/main..HEAD", KindNone},
		{"git:origin/main..HEAD", "origin/main..HEAD", KindGit},
		{"arc:trunk..HEAD", "trunk..HEAD", KindArc},
		{"arc:", "", KindArc},
	}
	for _, c := range cases {
		gotSpec, gotKind := parseRange(c.in)
		if gotSpec != c.wantSpec || gotKind != c.wantKind {
			t.Errorf("parseRange(%q) = (%q,%s), want (%q,%s)", c.in, gotSpec, gotKind, c.wantSpec, c.wantKind)
		}
	}
}

func TestParseGitBlamePorcelain(t *testing.T) {
	raw := `7d3f0fcd5b1234567890abcdef1234567890abcd 1 1 1
author Andrey Abakumov
author-mail <a@example.com>
author-time 1700000000
author-tz +0300
summary Initial commit
filename foo.go
	package main`
	b := parseGitBlamePorcelain(raw)
	if b.Commit != "7d3f0fcd5b1234567890abcdef1234567890abcd" {
		t.Errorf("commit=%q", b.Commit)
	}
	if b.Author != "Andrey Abakumov" {
		t.Errorf("author=%q", b.Author)
	}
	if b.Date != "1700000000" {
		t.Errorf("date=%q", b.Date)
	}
	if b.Summary != "Initial commit" {
		t.Errorf("summary=%q", b.Summary)
	}
}

func TestParseArcBlameLine(t *testing.T) {
	cases := []struct {
		line       string
		wantCommit string
		wantAuthor string
		wantOK     bool
	}{
		{
			"abc1234 (Andrey Abakumov 2024-01-15 12:34:56 +0300  42) code line",
			"abc1234", "Andrey Abakumov", true,
		},
		{
			"deadbeef (someone 2023-12-01 09:00:00  1) x := 1",
			"deadbeef", "someone", true,
		},
	}
	for _, c := range cases {
		b, ok := parseArcBlameLine(c.line)
		if ok != c.wantOK {
			t.Errorf("ok=%v for %q", ok, c.line)
		}
		if b.Commit != c.wantCommit {
			t.Errorf("commit=%q, want %q", b.Commit, c.wantCommit)
		}
		if b.Author != c.wantAuthor {
			t.Errorf("author=%q, want %q", b.Author, c.wantAuthor)
		}
	}
	// Garbled input still returns at least the leading hash, if any.
	if b, ok := parseArcBlameLine("abc1234 garbled rest"); ok || b.Commit != "abc1234" {
		t.Errorf("partial parse: got (%+v, %v)", b, ok)
	}
}

func TestParseArcStatusPorcelain(t *testing.T) {
	raw := " M src/foo.go\nA  src/bar.go\nR  old.go -> new.go\n?? untracked.go\n"
	got := parseArcStatusPorcelain(raw, "/repo")
	wantPaths := []string{"/repo/src/foo.go", "/repo/src/bar.go", "/repo/new.go"}
	if len(got) != len(wantPaths) {
		t.Fatalf("got %d files, want %d (%v)", len(got), len(wantPaths), got)
	}
	for i, w := range wantPaths {
		if got[i] != w {
			t.Errorf("[%d] %q, want %q", i, got[i], w)
		}
	}
}

func TestOpenUnsupportedReturnsError(t *testing.T) {
	// Force an unsupported backend tag.
	if _, err := Open(Kind("nonsense"), t.TempDir()); err == nil {
		t.Error("expected error for unknown backend")
	}
}

func TestNoneVCSStub(t *testing.T) {
	n, _ := Open(KindNone, t.TempDir())
	if n.Kind() != KindNone {
		t.Fatalf("kind=%s", n.Kind())
	}
	if _, err := n.ChangedFiles(t.Context(), "HEAD"); err == nil {
		t.Error("none.ChangedFiles should error")
	}
}
