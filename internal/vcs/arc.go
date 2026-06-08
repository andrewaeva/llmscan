package vcs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// arcVCS implements VCS via the Yandex Arc (Arcanum) `arc` CLI.
// Arc is largely git-compatible at the surface level but uses its own
// repository layout (.arc/ instead of .git/). Where possible we keep behavior
// symmetric with gitVCS so the rest of the pipeline does not need to care.
type arcVCS struct{ root string }

func (a *arcVCS) Kind() Kind   { return KindArc }
func (a *arcVCS) Root() string { return a.root }

// runArc executes `arc <args...>` with a timeout and returns stdout. stderr
// is folded into the error.
func (a *arcVCS) runArc(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	if !hasCLI("arc") {
		return "", fmt.Errorf("arc: %w", ErrUnsupported)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "arc", args...) //nolint:gosec // args originate from internal callers
	cmd.Dir = a.root
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("arc %s: %s", strings.Join(args, " "), strings.TrimSpace(errBuf.String()))
	}
	return out.String(), nil
}

// ChangedFiles tries `arc log --name-only <range>` first and falls back to
// `arc diff --name-only <range>` when the former is unavailable for the
// requested range. An empty range queries `arc status --porcelain` for the
// working-copy modified/added/renamed set.
func (a *arcVCS) ChangedFiles(ctx context.Context, rangeSpec string) ([]string, error) {
	rangeSpec, _ = parseRange(rangeSpec)
	if rangeSpec == "" {
		out, err := a.runArc(ctx, 10*time.Second, "status", "--porcelain")
		if err != nil {
			return nil, err
		}
		return parseArcStatusPorcelain(out, a.root), nil
	}
	// Preferred: `arc log --name-only <range>`.
	if out, err := a.runArc(ctx, 15*time.Second, "log", "--name-only", rangeSpec); err == nil {
		files := parseArcLogNameOnly(out, a.root)
		if len(files) > 0 {
			return files, nil
		}
	}
	// Fallback: `arc diff --name-only <range>`.
	out, err := a.runArc(ctx, 15*time.Second, "diff", "--name-only", rangeSpec)
	if err != nil {
		return nil, err
	}
	return parseArcDiffNameOnly(out, a.root), nil
}

// parseArcStatusPorcelain extracts tracked file paths from `arc status
// --porcelain`. Lines starting with `?` (untracked) are skipped.
func parseArcStatusPorcelain(text, root string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) < 3 {
			continue
		}
		code := strings.TrimSpace(line[:2])
		if code == "" || code == "?" || strings.HasPrefix(code, "?") {
			continue
		}
		path := strings.TrimSpace(line[2:])
		if path == "" {
			continue
		}
		// "from -> to" for renames; pick destination.
		if i := strings.Index(path, " -> "); i >= 0 {
			path = path[i+4:]
		}
		out = append(out, filepath.Join(root, path))
	}
	return out
}

// parseArcLogNameOnly pulls bare file paths from `arc log --name-only` output,
// ignoring metadata header lines that contain a colon (e.g. "commit:",
// "author:", "date:") or are empty.
func parseArcLogNameOnly(text, root string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, ":") && !strings.ContainsAny(line, "/.") {
			continue
		}
		if strings.HasPrefix(line, "commit ") || strings.HasPrefix(line, "Author") || strings.HasPrefix(line, "Date") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, filepath.Join(root, line))
	}
	return out
}

// parseArcDiffNameOnly returns absolute paths from `arc diff --name-only`.
func parseArcDiffNameOnly(text, root string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, filepath.Join(root, line))
	}
	return out
}

// arcBlameLineRE matches a typical `arc blame` line, e.g.:
//
//	<hash> (Author Name 2024-01-15 12:34:56 +0300  42) source code...
//
// where the parenthesised block carries author, date and 1-based line number.
var arcBlameLineRE = regexp.MustCompile(`^([0-9a-fA-F]{6,40})\s+\((.+?)\s+(\d{4}-\d{2}-\d{2}[T ]?\S*)(?:\s+[+\-]\d{4})?\s+(\d+)\)\s?(.*)$`)

// parseArcBlameLine parses one `arc blame` output line into a BlameLine. If
// the format is unexpected, returns a BlameLine with whatever could be salvaged.
func parseArcBlameLine(line string) (BlameLine, bool) {
	m := arcBlameLineRE.FindStringSubmatch(strings.TrimRight(line, "\r"))
	if m == nil {
		// Best-effort partial: try to pull at least the commit hash.
		fields := strings.Fields(line)
		if len(fields) > 0 && len(fields[0]) >= 6 {
			return BlameLine{Commit: fields[0]}, false
		}
		return BlameLine{}, false
	}
	return BlameLine{
		Commit:  m[1],
		Author:  strings.TrimSpace(m[2]),
		Date:    strings.TrimSpace(m[3]),
		Summary: strings.TrimSpace(m[5]),
	}, true
}

// Blame returns blame for a single line. We try `arc blame -L N,N <file>`
// first; if that flag is not supported, fall back to `arc blame <file>` and
// pick the matching line.
func (a *arcVCS) Blame(ctx context.Context, file string, line int) (BlameLine, error) {
	if line <= 0 {
		line = 1
	}
	rel := file
	if filepath.IsAbs(file) {
		if r, err := filepath.Rel(a.root, file); err == nil {
			rel = r
		}
	}
	if out, err := a.runArc(ctx, 10*time.Second, "blame", "-L", fmt.Sprintf("%d,%d", line, line), rel); err == nil {
		for _, ln := range strings.Split(out, "\n") {
			if ln == "" {
				continue
			}
			if b, ok := parseArcBlameLine(ln); ok {
				return b, nil
			}
		}
	}
	out, err := a.runArc(ctx, 20*time.Second, "blame", rel)
	if err != nil {
		return BlameLine{}, err
	}
	lines := strings.Split(out, "\n")
	idx := line - 1
	if idx < 0 || idx >= len(lines) {
		return BlameLine{}, fmt.Errorf("arc blame: line %d beyond EOF", line)
	}
	if b, ok := parseArcBlameLine(lines[idx]); ok {
		return b, nil
	}
	// Partial fallback: at least try to pull the hash off the front.
	if b, _ := parseArcBlameLine(lines[idx]); b.Commit != "" {
		return b, nil
	}
	return BlameLine{}, fmt.Errorf("arc blame: cannot parse line %d", line)
}

// CurrentBranch reads `arc branch --show-current`; falls back to scanning the
// first line of `arc status` which usually starts with "On branch <name>".
func (a *arcVCS) CurrentBranch(ctx context.Context) (string, error) {
	if out, err := a.runArc(ctx, 5*time.Second, "branch", "--show-current"); err == nil {
		if br := strings.TrimSpace(out); br != "" {
			return br, nil
		}
	}
	out, err := a.runArc(ctx, 5*time.Second, "status")
	if err != nil {
		return "", err
	}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "On branch ") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "On branch ")), nil
		}
	}
	return "", errors.New("arc: cannot determine current branch")
}

// IsTracked checks `arc info <file>`; treats non-zero exit as "untracked".
// When `arc info` is unavailable, falls back to scanning `arc status --
// <file>` output.
func (a *arcVCS) IsTracked(ctx context.Context, file string) (bool, error) {
	if file == "" {
		return false, errors.New("empty file")
	}
	rel := file
	if filepath.IsAbs(file) {
		if r, err := filepath.Rel(a.root, file); err == nil {
			rel = r
		}
	}
	if _, err := a.runArc(ctx, 5*time.Second, "info", rel); err == nil {
		return true, nil
	} else if errors.Is(err, ErrUnsupported) {
		// arc CLI is unavailable — surface it like the other methods rather
		// than silently reporting the file as untracked.
		return false, err
	}
	out, err := a.runArc(ctx, 5*time.Second, "status", "--porcelain", "--", rel)
	if err != nil {
		return false, nil
	}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "?") {
			return false, nil
		}
	}
	return true, nil
}
