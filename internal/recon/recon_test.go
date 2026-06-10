package recon

import (
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/types"
)

func TestSamplePrioritisesEntryPointsAndConfig(t *testing.T) {
	files := []types.FileTarget{
		{Path: "vendor/lib/util.go"},
		{Path: "internal/util/helpers.go"},
		{Path: "cmd/server/main.go"},
		{Path: "package.json"},
		{Path: "src/handlers/auth.go"},
		{Path: "src/routes/index.ts"},
		{Path: "test/fixtures/sample.go"},
	}
	entries := []callgraph.Info{
		{File: "cmd/server/main.go", Func: "main"},
		{File: "src/handlers/auth.go", Func: "Login"},
	}
	got := Sample(files, entries, 5)
	if len(got) == 0 {
		t.Fatal("Sample returned nothing")
	}
	paths := make([]string, 0, len(got))
	for _, f := range got {
		paths = append(paths, f.Path)
	}
	// Top picks should include entry points + config; vendor/test should not lead.
	top := strings.Join(paths[:min(3, len(paths))], ",")
	for _, want := range []string{"cmd/server/main.go", "src/handlers/auth.go", "package.json"} {
		if !strings.Contains(top, want) {
			t.Errorf("expected %q in top picks, got %v", want, paths)
		}
	}
	for _, junk := range []string{"vendor/", "test/fixtures/"} {
		for _, p := range paths {
			if strings.Contains(p, junk) {
				t.Errorf("did not expect %q-class file in sample: %v", junk, paths)
			}
		}
	}
}

func TestSampleRespectsCap(t *testing.T) {
	files := make([]types.FileTarget, 200)
	for i := range files {
		files[i] = types.FileTarget{Path: "a/b/" + string(rune('a'+i%26)) + ".go"}
	}
	got := Sample(files, nil, 10)
	if len(got) > 10 {
		t.Errorf("cap not respected: got %d", len(got))
	}
}
