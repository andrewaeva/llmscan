// Package vcs provides a small, provider-agnostic abstraction over version
// control systems used by llmscan: git and Yandex Arc (Arcanum). Callers can
// detect the active VCS automatically based on filesystem markers (.git/ or
// .arc/) or open a backend explicitly.
//
// The interface is intentionally minimal: enough to drive incremental scans
// (--diff <range>) and the blame tool used by the deep sub-agent. Implementations
// shell out to the corresponding CLI; if the CLI is missing, methods return a
// descriptive error rather than panicking — callers should degrade gracefully.
package vcs

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Kind enumerates supported VCS backends.
type Kind string

// Supported VCS backends.
const (
	KindGit  Kind = "git"
	KindArc  Kind = "arc"
	KindNone Kind = "none"
)

// BlameLine is the small payload returned by Blame. Date is ISO-8601 when
// available; backends may leave fields empty when they cannot extract them.
type BlameLine struct {
	Commit  string `json:"commit"`
	Author  string `json:"author"`
	Date    string `json:"date"`
	Summary string `json:"summary"`
}

// VCS is the provider-agnostic interface used by the pipeline and sandbox.
type VCS interface {
	// Kind returns this backend's tag (git/arc/none).
	Kind() Kind
	// Root returns the working tree root (absolute path).
	Root() string
	// ChangedFiles returns absolute paths of files changed in rangeSpec.
	// rangeSpec may carry a backend-prefix ("git:" / "arc:") which is stripped
	// by Detect/Open; backends should handle a bare range. An empty rangeSpec
	// yields the working-copy modified set (when supported) or an empty slice.
	ChangedFiles(ctx context.Context, rangeSpec string) ([]string, error)
	// Blame returns blame info for a single 1-based line.
	Blame(ctx context.Context, file string, line int) (BlameLine, error)
	// CurrentBranch returns the active branch name (best-effort).
	CurrentBranch(ctx context.Context) (string, error)
	// IsTracked reports whether `file` is tracked by this VCS.
	IsTracked(ctx context.Context, file string) (bool, error)
}

// ErrUnsupported is returned by Open when the requested backend is not
// supported on this platform (CLI not installed).
var ErrUnsupported = errors.New("vcs: backend not supported on this host")

// parseRange strips an optional "git:"/"arc:" prefix from rangeSpec.
// It also returns the implied Kind (KindNone when no prefix was present).
func parseRange(rangeSpec string) (string, Kind) {
	if rangeSpec == "" {
		return "", KindNone
	}
	switch {
	case strings.HasPrefix(rangeSpec, "git:"):
		return strings.TrimPrefix(rangeSpec, "git:"), KindGit
	case strings.HasPrefix(rangeSpec, "arc:"):
		return strings.TrimPrefix(rangeSpec, "arc:"), KindArc
	}
	return rangeSpec, KindNone
}

// SplitRange exposes parseRange to external callers (pipeline routing).
func SplitRange(rangeSpec string) (string, Kind) { return parseRange(rangeSpec) }

// Open forces a specific backend rooted at `root`. Returns ErrUnsupported if
// the corresponding CLI is missing.
func Open(kind Kind, root string) (VCS, error) {
	switch kind {
	case KindGit:
		if !hasCLI("git") {
			return nil, fmt.Errorf("%w: git CLI not on PATH", ErrUnsupported)
		}
		return &gitVCS{root: root}, nil
	case KindArc:
		if !hasCLI("arc") {
			return nil, fmt.Errorf("%w: arc CLI not on PATH", ErrUnsupported)
		}
		return &arcVCS{root: root}, nil
	case KindNone:
		return noneVCS{root: root}, nil
	}
	return nil, fmt.Errorf("vcs: unknown backend %q", kind)
}

// noneVCS is a stub used when no markers are present; all calls return errors
// or zero values, never panic.
type noneVCS struct{ root string }

func (noneVCS) Kind() Kind                                          { return KindNone }
func (n noneVCS) Root() string                                      { return n.root }
func (noneVCS) ChangedFiles(context.Context, string) ([]string, error) {
	return nil, errors.New("vcs: no VCS detected")
}
func (noneVCS) Blame(context.Context, string, int) (BlameLine, error) {
	return BlameLine{}, errors.New("vcs: no VCS detected")
}
func (noneVCS) CurrentBranch(context.Context) (string, error) {
	return "", errors.New("vcs: no VCS detected")
}
func (noneVCS) IsTracked(context.Context, string) (bool, error) {
	return false, errors.New("vcs: no VCS detected")
}
