package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestSandbox(t *testing.T) *Sandbox {
	t.Helper()
	dir := t.TempDir()
	// Layout:
	//   dir/
	//     main.go        -> small file with a few lines
	//     pkg/
	//       util.go
	//     secret.txt
	if err := os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pkg", "util.go"),
		[]byte("package pkg\n\nfunc Sum(a, b int) int { return a + b }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("topsecret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, err := NewSandbox(dir)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	return sb
}

func TestReadFile_OK(t *testing.T) {
	sb := newTestSandbox(t)
	out, err := sb.ReadFile("main.go", 1, 5)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(out, "package main") {
		t.Errorf("expected 'package main' in output, got: %s", out)
	}
	if !strings.Contains(out, "lines 1-5") {
		t.Errorf("expected line header, got: %s", out)
	}
}

func TestReadFile_PathTraversal(t *testing.T) {
	sb := newTestSandbox(t)
	cases := []string{
		"../../../etc/passwd",
		"/etc/passwd",
		"main.go/../../../etc/passwd",
	}
	for _, p := range cases {
		if _, err := sb.ReadFile(p, 0, 0); err == nil {
			t.Errorf("expected sandbox to reject %q", p)
		}
	}
}

func TestReadFile_OutOfRangeStart(t *testing.T) {
	sb := newTestSandbox(t)
	if _, err := sb.ReadFile("main.go", 999, 0); err == nil {
		t.Error("expected error for start beyond EOF")
	}
}

func TestGrep_FindsMatch(t *testing.T) {
	sb := newTestSandbox(t)
	out, err := sb.Grep("func", "", 100)
	if err != nil {
		t.Fatalf("Grep: %v", err)
	}
	if !strings.Contains(out, "main.go") || !strings.Contains(out, "util.go") {
		t.Errorf("expected hits in both files, got: %s", out)
	}
	if !strings.Contains(out, "total matches:") {
		t.Errorf("expected summary line, got: %s", out)
	}
}

func TestGrep_BadRegex(t *testing.T) {
	sb := newTestSandbox(t)
	if _, err := sb.Grep("(unclosed", "", 10); err == nil {
		t.Error("expected regex error")
	}
}

func TestListDir(t *testing.T) {
	sb := newTestSandbox(t)
	out, err := sb.ListDir(".")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if !strings.Contains(out, "main.go") || !strings.Contains(out, "pkg") {
		t.Errorf("expected to see main.go and pkg in listing, got: %s", out)
	}
}

func TestListDir_PathTraversal(t *testing.T) {
	sb := newTestSandbox(t)
	if _, err := sb.ListDir("../"); err == nil {
		t.Error("expected sandbox to reject parent listing")
	}
}

func TestReadFile_SymlinkEscape(t *testing.T) {
	sb := newTestSandbox(t)
	// Create a symlink inside the sandbox pointing outside.
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "outside.txt")
	if err := os.WriteFile(outside, []byte("not-yours\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(sb.Root, "evil.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if _, err := sb.ReadFile("evil.txt", 0, 0); err == nil {
		t.Error("expected sandbox to refuse symlink that escapes root")
	}
}
