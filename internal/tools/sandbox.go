// Package tools exposes a small, jailed set of read-only inspection tools that
// a sub-agent ("--deep") can call during its investigation. The sandbox is
// strictly scoped to a single root directory and refuses to read any path
// that escapes it (after symlink resolution).
//
// Tools provided:
//
//	read_file(path, start_line, end_line) -> {content, lines, total_lines}
//	grep(pattern, path_glob, max_matches)  -> {matches:[{file,line,text}]}
//	list_dir(path)                          -> {entries:[{name,type}]}
//	blame(path, line)                       -> {commit, author, date, summary} (git or arc)
//
// All output is size-limited so a runaway agent cannot blow the context window.
package tools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/andrewaeva/llmscan/internal/vcs"
)

// Defaults for output limits.
const (
	defaultMaxFileBytes = 512 * 1024
	defaultReadLines    = 500
	defaultGrepMatches  = 100
	defaultListEntries  = 200
	maxGrepFiles        = 5000
	maxResultBytes      = 32 * 1024 // hard cap on a single tool result
)

// Sandbox jails all reads to Root (canonicalized) and refuses escapes.
type Sandbox struct {
	Root         string // absolute, EvalSymlinks-resolved
	MaxFileBytes int

	// VCS, when non-nil, is used by Blame. When nil, Blame falls back to a
	// fresh vcs.Detect(Root) on first use — callers don't have to wire it up.
	VCS vcs.VCS

	// Index, when non-nil, enables higher-level inspection tools defined in
	// symbol.go (ReadSymbol, FindCallers, FindCallees, ListImports). Wire it
	// via SetIndex from the host pipeline after the AST and call graph have
	// been built; nil index ⇒ tools fall back to grep/read_file.
	Index *SymbolIndex
}

// NewSandbox creates a sandbox rooted at the canonical form of `root`.
// Returns an error if root does not exist or cannot be resolved.
func NewSandbox(root string) (*Sandbox, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("sandbox: abs: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// If the path doesn't exist yet, fall back to abs.
		resolved = abs
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("sandbox: stat root: %w", err)
	}
	if !st.IsDir() {
		// Single-file targets: root becomes the parent dir.
		resolved = filepath.Dir(resolved)
	}
	return &Sandbox{Root: resolved, MaxFileBytes: defaultMaxFileBytes}, nil
}

// resolve maps a user-supplied path (absolute or relative-to-root) to a
// canonical path that MUST live inside Root.
func (s *Sandbox) resolve(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	// Allow both "internal/llm/client.go" and absolute paths.
	if !filepath.IsAbs(p) {
		p = filepath.Join(s.Root, p)
	}
	clean := filepath.Clean(p)
	// Resolve symlinks if possible; ignore "does not exist" so that callers
	// can still get a structured error like fs.ErrNotExist downstream.
	if r, err := filepath.EvalSymlinks(clean); err == nil {
		clean = r
	}
	// Final jail check.
	rel, err := filepath.Rel(s.Root, clean)
	if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
		return "", fmt.Errorf("path escapes sandbox: %s", p)
	}
	return clean, nil
}

// ReadFile returns lines [start..end] inclusive (1-based). end<=0 means
// start+defaultReadLines. The result is truncated to MaxFileBytes.
func (s *Sandbox) ReadFile(path string, start, end int) (string, error) {
	abs, err := s.resolve(path)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return "", fmt.Errorf("is a directory: %s", path)
	}
	maxBytes := s.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxFileBytes
	}
	if st.Size() > int64(maxBytes)*4 {
		// Don't even open enormous files.
		return "", fmt.Errorf("file too large (%d bytes, cap %d)", st.Size(), maxBytes*4)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	lines := bytes.Split(raw, []byte("\n"))
	total := len(lines)
	if start <= 0 {
		start = 1
	}
	if end <= 0 || end < start {
		end = start + defaultReadLines - 1
	}
	if end > total {
		end = total
	}
	if start > total {
		return "", fmt.Errorf("start_line %d beyond EOF (file has %d lines)", start, total)
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "// %s (lines %d-%d of %d)\n", path, start, end, total)
	for i := start - 1; i < end && i < len(lines); i++ {
		fmt.Fprintf(&buf, "%5d  %s\n", i+1, lines[i])
		if buf.Len() > maxBytes {
			fmt.Fprintf(&buf, "...[truncated at %d bytes]\n", maxBytes)
			break
		}
	}
	return buf.String(), nil
}

// Grep returns up to maxMatches `pattern` hits inside files matching
// pathGlob (relative to root). pathGlob "" means the whole sandbox.
//
//nolint:gocyclo // recursive search with multiple filters and skip rules
func (s *Sandbox) Grep(pattern, pathGlob string, maxMatches int) (string, error) {
	if pattern == "" {
		return "", errors.New("empty pattern")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("regex: %w", err)
	}
	if maxMatches <= 0 {
		maxMatches = defaultGrepMatches
	}

	// Determine candidate file set.
	var candidates []string
	switch { //nolint:staticcheck // QF1002: multi-value alternative branches aren't a tagged switch
	case pathGlob == "" || pathGlob == "**" || pathGlob == ".":
		_ = filepath.WalkDir(s.Root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" || name == "dist" || name == "build" {
					return filepath.SkipDir
				}
				return nil
			}
			if len(candidates) >= maxGrepFiles {
				return filepath.SkipAll
			}
			candidates = append(candidates, p)
			return nil
		})
	default:
		// Honor a single glob; for safety, resolve dir part first.
		base := s.Root
		if dir, _ := filepath.Split(pathGlob); dir != "" {
			if abs, err := s.resolve(dir); err == nil {
				base = abs
			}
		}
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(s.Root, p)
			if matched, _ := filepath.Match(pathGlob, rel); matched {
				candidates = append(candidates, p)
			}
			return nil
		})
	}

	var buf bytes.Buffer
	matches := 0
	fmt.Fprintf(&buf, "// grep %q in %d files\n", pattern, len(candidates))
	for _, p := range candidates {
		if matches >= maxMatches {
			break
		}
		raw, err := os.ReadFile(p)
		if err != nil || len(raw) > s.MaxFileBytes*4 {
			continue
		}
		rel, _ := filepath.Rel(s.Root, p)
		for i, ln := range bytes.Split(raw, []byte("\n")) {
			if !re.Match(ln) {
				continue
			}
			text := strings.TrimSpace(string(ln))
			if len(text) > 240 {
				text = text[:240] + "..."
			}
			fmt.Fprintf(&buf, "%s:%d  %s\n", rel, i+1, text)
			matches++
			if matches >= maxMatches || buf.Len() > maxResultBytes {
				break
			}
		}
		if buf.Len() > maxResultBytes {
			fmt.Fprintf(&buf, "...[result truncated]\n")
			break
		}
	}
	fmt.Fprintf(&buf, "// total matches: %d\n", matches)
	return buf.String(), nil
}

// ListDir lists immediate children of `path`, capped at defaultListEntries.
func (s *Sandbox) ListDir(path string) (string, error) {
	if path == "" {
		path = "."
	}
	abs, err := s.resolve(path)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("not a directory: %s", path)
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var buf bytes.Buffer
	rel, _ := filepath.Rel(s.Root, abs)
	if rel == "" {
		rel = "."
	}
	fmt.Fprintf(&buf, "// %s (%d entries)\n", rel, len(entries))
	for i, e := range entries {
		if i >= defaultListEntries {
			fmt.Fprintf(&buf, "...[truncated at %d entries]\n", defaultListEntries)
			break
		}
		kind := "file"
		if e.IsDir() {
			kind = "dir "
		}
		fmt.Fprintf(&buf, "  %s  %s\n", kind, e.Name())
	}
	return buf.String(), nil
}

// Blame returns blame info for a single line, dispatching to whichever VCS
// backend the sandbox is wired to. If no VCS is configured, the sandbox runs
// vcs.Detect(Root) lazily so existing callers continue to work.
//
// The previous name was GitBlame; it's kept as a thin alias for backward
// compatibility.
func (s *Sandbox) Blame(path string, line int) (string, error) {
	abs, err := s.resolve(path)
	if err != nil {
		return "", err
	}
	if line <= 0 {
		line = 1
	}
	rel, _ := filepath.Rel(s.Root, abs)
	v := s.VCS
	if v == nil {
		detected, derr := vcs.Detect(s.Root)
		if derr != nil || detected == nil || detected.Kind() == vcs.KindNone {
			return "", fmt.Errorf("blame: no VCS detected at %s", s.Root)
		}
		v = detected
	}
	ctx, cancel := contextWithTimeout(10 * time.Second)
	defer cancel()
	b, err := v.Blame(ctx, rel, line)
	if err != nil {
		return "", fmt.Errorf("%s blame: %v", v.Kind(), err)
	}
	res := map[string]string{
		"commit":  b.Commit,
		"author":  b.Author,
		"date":    b.Date,
		"summary": b.Summary,
		"path":    rel,
		"line":    fmt.Sprintf("%d", line),
		"vcs":     string(v.Kind()),
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// GitBlame is preserved as a thin alias so callers outside the deep agent
// (and tests) that still reference it keep compiling.
//
// Deprecated: use Blame.
func (s *Sandbox) GitBlame(path string, line int) (string, error) {
	return s.Blame(path, line)
}
