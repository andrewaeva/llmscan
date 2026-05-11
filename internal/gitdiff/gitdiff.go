// Package gitdiff computes the set of files changed between two git refs.
// Used by --diff mode to scan only PR-affected files (plus reverse deps).
package gitdiff

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ChangedFiles returns absolute paths of files changed in `range` (e.g. "origin/main...HEAD").
// `repoRoot` is the working tree root.
func ChangedFiles(repoRoot, refRange string) ([]string, error) {
	if refRange == "" {
		return nil, nil
	}
	cmd := exec.Command("git", "-C", repoRoot, "diff", "--name-only", "--diff-filter=ACMR", refRange)
	var out bytes.Buffer
	cmd.Stdout = &out
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff: %w: %s", err, errBuf.String())
	}
	var files []string
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		abs := filepath.Join(repoRoot, line)
		files = append(files, abs)
	}
	return files, nil
}

// IsRepo reports whether the path is inside a git work tree.
func IsRepo(path string) bool {
	cmd := exec.Command("git", "-C", path, "rev-parse", "--is-inside-work-tree")
	return cmd.Run() == nil
}
