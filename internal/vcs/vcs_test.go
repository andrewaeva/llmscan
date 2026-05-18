package vcs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

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

func TestSplitRange(t *testing.T) {
	spec, kind := SplitRange("git:HEAD~1..HEAD")
	if spec != "HEAD~1..HEAD" || kind != KindGit {
		t.Fatalf("SplitRange returned (%q, %s)", spec, kind)
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

func TestParseArcLogAndDiffNameOnly(t *testing.T) {
	logOut := `
commit abcdef
Author: Test User
Date: yesterday

src/foo.go
src/foo.go
README.md
`
	gotLog := parseArcLogNameOnly(logOut, "/repo")
	if len(gotLog) != 2 {
		t.Fatalf("log paths=%v", gotLog)
	}
	if gotLog[0] != "/repo/src/foo.go" || gotLog[1] != "/repo/README.md" {
		t.Fatalf("unexpected log paths=%v", gotLog)
	}

	diffOut := "src/foo.go\nREADME.md\n"
	gotDiff := parseArcDiffNameOnly(diffOut, "/repo")
	if len(gotDiff) != 2 {
		t.Fatalf("diff paths=%v", gotDiff)
	}
	if gotDiff[0] != "/repo/src/foo.go" || gotDiff[1] != "/repo/README.md" {
		t.Fatalf("unexpected diff paths=%v", gotDiff)
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

func TestHasCLI(t *testing.T) {
	if !hasCLI("git") {
		t.Fatal("expected git on PATH for integration tests")
	}
	if hasCLI("definitely-not-a-real-cli") {
		t.Fatal("unexpected bogus CLI hit")
	}
}

func TestOpenGitAndNone(t *testing.T) {
	dir := t.TempDir()
	g, err := Open(KindGit, dir)
	if err != nil {
		t.Fatalf("Open git: %v", err)
	}
	if g.Kind() != KindGit || g.Root() != dir {
		t.Fatalf("unexpected git vcs: kind=%s root=%s", g.Kind(), g.Root())
	}

	n, err := Open(KindNone, dir)
	if err != nil {
		t.Fatalf("Open none: %v", err)
	}
	if n.Kind() != KindNone || n.Root() != dir {
		t.Fatalf("unexpected none vcs: kind=%s root=%s", n.Kind(), n.Root())
	}
}

func TestGitVCSEndToEnd(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.name", "Test User")
	runGit(t, dir, "config", "user.email", "test@example.com")

	tracked := filepath.Join(dir, "tracked.go")
	if err := os.WriteFile(tracked, []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "tracked.go")
	runGit(t, dir, "commit", "-m", "first")

	if err := os.WriteFile(tracked, []byte("package main\n// second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(dir, "second.go")
	if err := os.WriteFile(second, []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "tracked.go", "second.go")
	runGit(t, dir, "commit", "-m", "second")

	untracked := filepath.Join(dir, "scratch.go")
	if err := os.WriteFile(untracked, []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	g := &gitVCS{root: dir}
	files, err := g.ChangedFiles(context.Background(), "HEAD~1..HEAD")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("changed files=%v", files)
	}
	if files[0] != tracked && files[1] != tracked {
		t.Fatalf("tracked.go missing from changed files=%v", files)
	}
	if files[0] != second && files[1] != second {
		t.Fatalf("second.go missing from changed files=%v", files)
	}

	branch, err := g.CurrentBranch(context.Background())
	if err != nil {
		t.Fatalf("CurrentBranch: %v", err)
	}
	if strings.TrimSpace(branch) == "" {
		t.Fatal("expected non-empty branch name")
	}

	isTracked, err := g.IsTracked(context.Background(), tracked)
	if err != nil || !isTracked {
		t.Fatalf("IsTracked(tracked)=(%v,%v)", isTracked, err)
	}
	isTracked, err = g.IsTracked(context.Background(), untracked)
	if err != nil || isTracked {
		t.Fatalf("IsTracked(untracked)=(%v,%v)", isTracked, err)
	}

	blame, err := g.Blame(context.Background(), tracked, 2)
	if err != nil {
		t.Fatalf("Blame: %v", err)
	}
	if blame.Commit == "" || blame.Author != "Test User" || blame.Summary == "" {
		t.Fatalf("unexpected blame: %+v", blame)
	}
}

func TestArcMethodsReturnUnsupportedWithoutCLI(t *testing.T) {
	if hasCLI("arc") {
		t.Skip("arc CLI is available on this host")
	}

	a := &arcVCS{root: t.TempDir()}
	if _, err := a.ChangedFiles(context.Background(), ""); err == nil {
		t.Fatal("expected unsupported error from ChangedFiles")
	}
	if _, err := a.Blame(context.Background(), "x.go", 1); err == nil {
		t.Fatal("expected unsupported error from Blame")
	}
	if _, err := a.CurrentBranch(context.Background()); err == nil {
		t.Fatal("expected unsupported error from CurrentBranch")
	}
	if _, err := a.IsTracked(context.Background(), "x.go"); err == nil {
		t.Fatal("expected unsupported error from IsTracked")
	}
}
