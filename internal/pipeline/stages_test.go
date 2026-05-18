package pipeline

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/vcs"
)

func TestConfiguredVCSKind(t *testing.T) {
	if got := configuredVCSKind("git"); got != vcs.KindGit {
		t.Fatalf("configuredVCSKind(git)=%s want %s", got, vcs.KindGit)
	}
	if got := configuredVCSKind("arc"); got != vcs.KindArc {
		t.Fatalf("configuredVCSKind(arc)=%s want %s", got, vcs.KindArc)
	}
	if got := configuredVCSKind("none"); got != vcs.KindNone {
		t.Fatalf("configuredVCSKind(none)=%s want %s", got, vcs.KindNone)
	}
	if got := configuredVCSKind("unknown"); got != vcs.KindNone {
		t.Fatalf("configuredVCSKind(unknown)=%s want %s", got, vcs.KindNone)
	}
}

func TestFilterFilesByPathKeepsInputOrder(t *testing.T) {
	files := []types.FileTarget{
		{Path: "b.go"},
		{Path: "a.go"},
		{Path: "c.go"},
	}
	keep := changedPathSet([]string{"a.go", "c.go"})
	out := filterFilesByPath(files, keep)
	if len(out) != 2 {
		t.Fatalf("out=%+v", out)
	}
	if out[0].Path != "a.go" || out[1].Path != "c.go" {
		t.Fatalf("unexpected order: %+v", out)
	}
}

func TestMergePriorityWithTopFanInLimitAndDedupe(t *testing.T) {
	priority := []string{"p2.go", "p1.go", "top2.go"}
	top := []string{"top1.go", "top2.go", "top3.go"}
	out := mergePriorityWithTopFanIn(priority, top, 2)
	want := []string{"top1.go", "top2.go", "p2.go", "p1.go"}
	if len(out) != len(want) {
		t.Fatalf("out=%v want=%v", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("out=%v want=%v", out, want)
		}
	}
}

func TestSkillUsesReflexion(t *testing.T) {
	cfg := config.Default()
	e := New(cfg)
	// Empty list means all skills enabled for reflexion.
	if !e.skillUsesReflexion("injection") {
		t.Fatal("expected true for empty reflexion list")
	}

	cfg.Precision.ReflexionSkills = []string{"auth", "crypto"}
	e = New(cfg)
	if !e.skillUsesReflexion("auth") {
		t.Fatal("expected auth to be enabled")
	}
	if e.skillUsesReflexion("injection") {
		t.Fatal("expected injection to be disabled")
	}
}
