package vcs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// gitVCS implements VCS via the `git` CLI.
type gitVCS struct{ root string }

func (g *gitVCS) Kind() Kind   { return KindGit }
func (g *gitVCS) Root() string { return g.root }

// ChangedFiles runs `git diff --name-only --diff-filter=ACMR <range>` and
// returns absolute paths. An empty rangeSpec returns nil (caller decides).
// A leading "git:" prefix is stripped for symmetry with arc.
func (g *gitVCS) ChangedFiles(ctx context.Context, rangeSpec string) ([]string, error) {
	rangeSpec, _ = parseRange(rangeSpec)
	if rangeSpec == "" {
		return nil, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", "-C", g.root, "diff", "--name-only", "--diff-filter=ACMR", rangeSpec) //nolint:gosec // rangeSpec validated by user, scoped to repoRoot
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff: %w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	var files []string
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		files = append(files, filepath.Join(g.root, line))
	}
	return files, nil
}

// Blame runs `git blame -L line,line --porcelain <file>` and parses the
// porcelain header lines.
func (g *gitVCS) Blame(ctx context.Context, file string, line int) (BlameLine, error) {
	if line <= 0 {
		line = 1
	}
	rel := file
	if filepath.IsAbs(file) {
		if r, err := filepath.Rel(g.root, file); err == nil {
			rel = r
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", "blame", "-L", fmt.Sprintf("%d,%d", line, line), "--porcelain", rel) //nolint:gosec // rel scoped to repo root
	cmd.Dir = g.root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return BlameLine{}, fmt.Errorf("git blame: %s", strings.TrimSpace(string(out)))
	}
	return parseGitBlamePorcelain(string(out)), nil
}

// parseGitBlamePorcelain pulls commit, author, summary and author-time out of
// `git blame --porcelain` output. Exported as a package-private helper so it
// can be unit-tested without a real git checkout.
func parseGitBlamePorcelain(text string) BlameLine {
	var b BlameLine
	for _, ln := range strings.Split(text, "\n") {
		switch {
		case b.Commit == "" && len(ln) >= 40 && !strings.ContainsAny(ln[:1], " \t"):
			b.Commit = strings.Fields(ln)[0]
		case strings.HasPrefix(ln, "author "):
			b.Author = strings.TrimPrefix(ln, "author ")
		case strings.HasPrefix(ln, "summary "):
			b.Summary = strings.TrimPrefix(ln, "summary ")
		case strings.HasPrefix(ln, "author-time "):
			b.Date = strings.TrimPrefix(ln, "author-time ")
		}
	}
	return b
}

func (g *gitVCS) CurrentBranch(ctx context.Context) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", "-C", g.root, "branch", "--show-current") //nolint:gosec // g.root is repository root from trusted detection
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// IsTracked returns true when `git ls-files --error-unmatch <file>` exits with
// status 0 — i.e. the file is part of the index.
func (g *gitVCS) IsTracked(ctx context.Context, file string) (bool, error) {
	if file == "" {
		return false, errors.New("empty file")
	}
	rel := file
	if filepath.IsAbs(file) {
		if r, err := filepath.Rel(g.root, file); err == nil {
			rel = r
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", "-C", g.root, "ls-files", "--error-unmatch", "--", rel) //nolint:gosec // rel scoped
	if err := cmd.Run(); err != nil {
		// non-zero exit means untracked; we don't surface that as a hard error.
		return false, nil
	}
	return true, nil
}
