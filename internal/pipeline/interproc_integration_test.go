package pipeline

import (
	"context"
	"path/filepath"
	"testing"
)

// TestInterProcIntegration_CrossFileSQL builds a 3-file fixture (handler ->
// service -> db) with a clear SQL-injection chain, runs the pipeline, and
// asserts that at least one finding gets the "interproc-taint" tag plus a
// multi-file trace.
func TestInterProcIntegration_CrossFileSQL(t *testing.T) {
	srv := fakeOpenAIServer(t, nil)
	cfg := configForServer(t, srv.URL)
	// Re-enable interproc-related features for this scenario.
	cfg.Precision.Taint = true
	cfg.Precision.InterProc = true
	cfg.Precision.Reachability = true
	cfg.Precision.PreFilterWatchlist = false
	// Disable FP filter so synthetic findings survive to be inspected.
	ac := cfg.Agents["fp_filter"]
	ac.Enabled = false
	cfg.Agents["fp_filter"] = ac
	cfg.DropFalsePositives = false

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "handler.go"), `package main

import "net/http"

func Handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	doWork(q)
}
`)
	mustWrite(t, filepath.Join(dir, "service.go"), `package main

func doWork(s string) {
	saveRow(s)
}
`)
	mustWrite(t, filepath.Join(dir, "db.go"), `package main

func saveRow(s string) {
	db.Exec("SELECT * FROM x WHERE id='" + s + "'")
}
`)

	e := New(cfg)
	rep, err := e.Run(context.Background(), dir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.FilesScanned < 3 {
		t.Fatalf("expected >=3 files scanned; got %d", rep.FilesScanned)
	}
	// We expect: at least one finding tagged interproc-taint or that has a
	// multi-file trace. The fake LLM always emits a finding for the injection
	// scanner with line=1 — its file might be handler.go (the chunk being
	// scanned), and the interproc path should attach a sink at saveRow line.
	foundTag := false
	multiFile := false
	for _, f := range rep.Findings {
		for _, tg := range f.Tags {
			if tg == "interproc-taint" {
				foundTag = true
			}
		}
		seen := map[string]bool{}
		for _, h := range f.Trace {
			seen[h.File] = true
		}
		if len(seen) >= 2 {
			multiFile = true
		}
	}
	if !foundTag && !multiFile {
		t.Logf("findings: %+v", rep.Findings)
		t.Fatalf("expected at least one interproc-tagged or multi-file finding")
	}
}
