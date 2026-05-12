package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
)

// Detect walks upward from `path` looking for the first VCS marker:
// `.git/` selects git, `.arc/` selects arc. Returns a noneVCS when neither is
// found. The search stops at the filesystem root.
//
// If the CLI for the detected backend is missing, Detect still returns a
// backend object — calls will fail descriptively, callers should degrade.
func Detect(path string) (VCS, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// If `abs` is a file, start from its parent.
	if st, err := os.Stat(abs); err == nil && !st.IsDir() {
		abs = filepath.Dir(abs)
	}
	cur := abs
	for {
		if isDir(filepath.Join(cur, ".git")) {
			return &gitVCS{root: cur}, nil
		}
		if isDir(filepath.Join(cur, ".arc")) {
			return &arcVCS{root: cur}, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return noneVCS{root: abs}, nil
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// hasCLI reports whether the named tool is on PATH.
func hasCLI(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
