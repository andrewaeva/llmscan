package gitdiff

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// gitAvailable returns true if `git` is on PATH; otherwise tests that need it skip.
func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func setupRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-b", "main", "-q")
	runGit(t, dir, "config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "a.txt")
	runGit(t, dir, "commit", "-q", "-m", "initial")
	return dir
}

func TestIsRepo(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	dir := setupRepo(t)
	if !IsRepo(dir) {
		t.Errorf("IsRepo(%q) = false, want true", dir)
	}
	other := t.TempDir()
	if IsRepo(other) {
		t.Errorf("IsRepo on non-repo must be false")
	}
}

func TestChangedFiles(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	dir := setupRepo(t)
	// new commit changing a.txt and adding b.txt
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "change")

	files, err := ChangedFiles(dir, "HEAD~1...HEAD")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("expected at least 2 files, got %v", files)
	}
	set := map[string]bool{}
	for _, f := range files {
		set[filepath.Base(f)] = true
	}
	if !set["a.txt"] || !set["b.txt"] {
		t.Errorf("expected a.txt and b.txt in changed set, got %v", set)
	}
}

func TestChangedFilesNonRepo(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	_, err := ChangedFiles(t.TempDir(), "HEAD~1...HEAD")
	if err == nil {
		t.Error("expected error for non-repo")
	}
}
