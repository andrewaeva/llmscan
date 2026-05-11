package cache

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func openTest(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "cache.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOpenAndClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if db == nil {
		t.Fatal("nil DB")
	}
	if got := db.Path(); got != path {
		t.Errorf("Path()=%q want %q", got, path)
	}
	if err := db.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("cache file not created: %v", err)
	}
}

func TestOpenCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deep", "nested", "cache.db")
	db, err := Open(nested)
	if err != nil {
		t.Fatalf("open with nested path: %v", err)
	}
	defer db.Close()
	if _, err := os.Stat(nested); err != nil {
		t.Errorf("cache file not created: %v", err)
	}
}

func TestEmbeddingRoundtrip(t *testing.T) {
	db := openTest(t)
	vec := []float32{0.1, -0.5, 3.14, 0, float32(math.Pi)}
	if err := db.PutEmbedding("k1", "openai", "text-embed", vec); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok := db.GetEmbedding("k1", "openai", "text-embed")
	if !ok {
		t.Fatal("not found")
	}
	if len(got) != len(vec) {
		t.Fatalf("len=%d want %d", len(got), len(vec))
	}
	for i, v := range vec {
		if got[i] != v {
			t.Errorf("got[%d]=%v want %v", i, got[i], v)
		}
	}
	// Miss with wrong provider/model
	if _, ok := db.GetEmbedding("k1", "other", "text-embed"); ok {
		t.Error("expected miss on different provider")
	}
	if _, ok := db.GetEmbedding("k1", "openai", "other"); ok {
		t.Error("expected miss on different model")
	}
	if _, ok := db.GetEmbedding("missing", "openai", "text-embed"); ok {
		t.Error("expected miss on unknown key")
	}
}

func TestEmbeddingOverwrite(t *testing.T) {
	db := openTest(t)
	_ = db.PutEmbedding("k", "p", "m", []float32{1, 2})
	if err := db.PutEmbedding("k", "p", "m", []float32{9, 8, 7}); err != nil {
		t.Fatal(err)
	}
	got, ok := db.GetEmbedding("k", "p", "m")
	if !ok || len(got) != 3 || got[0] != 9 {
		t.Errorf("overwrite failed: got=%v ok=%v", got, ok)
	}
}

func TestBaselineRoundtrip(t *testing.T) {
	db := openTest(t)
	items := map[string]string{
		"fp1": "finding-1",
		"fp2": "finding-2",
		"fp3": "finding-3",
	}
	if err := db.SaveBaseline(items); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := db.LoadBaseline()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("got %d entries want 3: %v", len(got), got)
	}
	for k := range items {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %q", k)
		}
	}
}

func TestBaselineEmptyLoad(t *testing.T) {
	db := openTest(t)
	got, err := db.LoadBaseline()
	if err != nil {
		t.Fatalf("load empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestEncodeDecodeFloats(t *testing.T) {
	cases := [][]float32{
		{},
		{0},
		{1.5, -2.5, 0, 3.14},
	}
	for _, v := range cases {
		b := encodeFloats(v)
		got := decodeFloats(b)
		if len(got) != len(v) {
			t.Errorf("len mismatch: got %d want %d", len(got), len(v))
			continue
		}
		for i := range v {
			if got[i] != v[i] {
				t.Errorf("[%d] got=%v want=%v", i, got[i], v[i])
			}
		}
	}
}

func BenchmarkPutEmbedding(b *testing.B) {
	dir := b.TempDir()
	db, err := Open(filepath.Join(dir, "c.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	vec := make([]float32, 1536)
	for i := range vec {
		vec[i] = float32(i) * 0.001
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = db.PutEmbedding("k", "p", "m", vec)
	}
}

func BenchmarkEncodeFloats(b *testing.B) {
	vec := make([]float32, 1536)
	for i := range vec {
		vec[i] = float32(i)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = encodeFloats(vec)
	}
}
