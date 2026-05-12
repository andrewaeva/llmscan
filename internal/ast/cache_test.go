package ast

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCache_LookupMissThenHit(t *testing.T) {
	dir := t.TempDir()
	cpath := filepath.Join(dir, "ast.db")
	c, err := OpenCache(cpath)
	if err != nil {
		t.Fatalf("OpenCache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	src := []byte("package main\n\nfunc Foo() {}\n")
	tmp := filepath.Join(dir, "main.go")
	if err := os.WriteFile(tmp, src, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := c.Lookup(tmp, src, LangGo); err != nil || ok {
		t.Fatalf("first Lookup: ok=%v err=%v", ok, err)
	}
	a, err := Parse(context.Background(), tmp, src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := c.Store(a); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, ok, err := c.Lookup(tmp, src, LangGo)
	if err != nil || !ok || got == nil {
		t.Fatalf("second Lookup: ok=%v err=%v got=%v", ok, err, got)
	}
	if got.Language != LangGo {
		t.Errorf("Language=%s, want go", got.Language)
	}
	if len(got.Symbols) == 0 {
		t.Errorf("expected at least one symbol")
	}
	if string(FileSource(got)) != string(src) {
		t.Errorf("source mismatch")
	}
	st := c.Stats()
	if st.Hits != 1 || st.Misses != 1 || st.Stores != 1 {
		t.Errorf("stats=%+v", st)
	}
}

func TestCache_ContentChangeInvalidates(t *testing.T) {
	dir := t.TempDir()
	c, err := OpenCache(filepath.Join(dir, "ast.db"))
	if err != nil {
		t.Fatalf("OpenCache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	src1 := []byte("package main\n\nfunc Foo() {}\n")
	src2 := []byte("package main\n\nfunc Bar() {}\n")
	tmp := filepath.Join(dir, "main.go")
	_ = os.WriteFile(tmp, src1, 0o644)
	a, _ := Parse(context.Background(), tmp, src1)
	_ = c.Store(a)

	if _, ok, _ := c.Lookup(tmp, src2, LangGo); ok {
		t.Error("expected miss for changed content")
	}
}

func TestCache_Clear(t *testing.T) {
	dir := t.TempDir()
	c, err := OpenCache(filepath.Join(dir, "ast.db"))
	if err != nil {
		t.Fatalf("OpenCache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	src := []byte("package main\nfunc X() {}\n")
	a, _ := Parse(context.Background(), filepath.Join(dir, "x.go"), src)
	_ = c.Store(a)
	if _, ok, _ := c.Lookup("x", src, LangGo); !ok {
		t.Fatal("precondition: should have been a hit")
	}
	if err := c.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, ok, _ := c.Lookup("x", src, LangGo); ok {
		t.Error("expected miss after Clear")
	}
}

func TestCache_NilSafe(t *testing.T) {
	var c *Cache
	if _, ok, err := c.Lookup("x", []byte("a"), LangGo); ok || err != nil {
		t.Errorf("nil cache lookup: ok=%v err=%v", ok, err)
	}
	if err := c.Store(&FileAST{Path: "x"}); err != nil {
		t.Errorf("nil cache store: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("nil cache close: %v", err)
	}
}

func TestCache_Concurrent(t *testing.T) {
	dir := t.TempDir()
	c, err := OpenCache(filepath.Join(dir, "ast.db"))
	if err != nil {
		t.Fatalf("OpenCache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			src := []byte("package main\nfunc F" + string(rune('A'+i)) + "() {}\n")
			a, err := Parse(context.Background(), "x.go", src)
			if err != nil {
				t.Errorf("Parse: %v", err)
				return
			}
			if err := c.Store(a); err != nil {
				t.Errorf("Store: %v", err)
			}
			if _, ok, err := c.Lookup("x.go", src, LangGo); !ok || err != nil {
				t.Errorf("Lookup: ok=%v err=%v", ok, err)
			}
		}(i)
	}
	wg.Wait()
}
