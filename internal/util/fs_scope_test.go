package util

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalkScoped_NoScope(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.go"), "package a\n")
	writeFile(t, filepath.Join(dir, "sub", "b.go"), "package b\n")
	got, err := WalkScoped(dir, WalkOptions{})
	if err != nil {
		t.Fatalf("WalkScoped: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d files, want 2 (%v)", len(got), got)
	}
}

func TestWalkScoped_ScopeRoots(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.go"), "package a\n")
	writeFile(t, filepath.Join(dir, "pkg1", "x.go"), "package x\n")
	writeFile(t, filepath.Join(dir, "pkg2", "y.go"), "package y\n")
	writeFile(t, filepath.Join(dir, "pkg3", "z.go"), "package z\n")
	got, err := WalkScoped(dir, WalkOptions{
		ScopeRoots: []string{"pkg1", "pkg2"},
	})
	if err != nil {
		t.Fatalf("WalkScoped: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d files, want 2 (%v)", len(got), got)
	}
	names := map[string]bool{}
	for _, f := range got {
		names[filepath.Base(f.Path)] = true
	}
	if !names["x.go"] || !names["y.go"] {
		t.Errorf("missing expected files: %v", names)
	}
	if names["a.go"] || names["z.go"] {
		t.Errorf("unexpected files leaked in: %v", names)
	}
}

func TestWalkScoped_MaxFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		writeFile(t, filepath.Join(dir, "f"+string(rune('0'+i))+".go"), "package a\n")
	}
	got, err := WalkScoped(dir, WalkOptions{MaxFiles: 3})
	if !errors.Is(err, ErrTooManyFiles) {
		t.Fatalf("expected ErrTooManyFiles, got %v", err)
	}
	if len(got) > 3 {
		t.Errorf("returned slice should be capped, got %d", len(got))
	}
}

func TestWalkScoped_ScopeEscapeRejected(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "z.go"), "package z\n")
	_, err := WalkScoped(dir, WalkOptions{ScopeRoots: []string{outside}})
	if err == nil {
		t.Error("expected error when scope escapes root")
	}
}
