package util

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/andrewaeva/llmscan/internal/types"
)

// ErrTooManyFiles is returned by WalkScoped when the post-filter file count
// exceeds the configured MaxFiles limit. The caller is expected to surface
// this to the user with hints about --scope-root and --max-files.
var ErrTooManyFiles = errors.New("too many files (use --scope-root or increase --max-files)")

// WalkOptions controls WalkScoped behavior. All fields are optional.
//
//   - ScopeRoots restricts traversal to one or more sub-paths under `root`.
//     Each entry may be absolute or relative to the caller's current working
//     directory; the helper makes it absolute internally. When empty, the
//     whole `root` is walked.
//   - MaxFiles bounds the resulting target list after filters; 0 = unbounded.
//   - Include / Exclude / MaxBytes / FollowSymlinks mirror Walk() semantics.
type WalkOptions struct {
	ScopeRoots     []string
	MaxFiles       int
	Include        []string
	Exclude        []string
	MaxBytes       int
	FollowSymlinks bool
}

// WalkScoped is the monorepo-aware variant of Walk. When ScopeRoots is empty
// the behavior is identical to Walk(root, ...). When ScopeRoots is non-empty,
// each scope is walked independently and the results are merged (deduplicated
// by absolute path, preserving first-seen order).
//
// MaxFiles, when > 0, caps the merged result; exceeding it yields
// ErrTooManyFiles together with the (truncated) slice so callers can inspect
// the partial set if desired.
func WalkScoped(root string, opts WalkOptions) ([]types.FileTarget, error) {
	roots, err := resolveScopeRoots(root, opts.ScopeRoots)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []types.FileTarget
	for _, r := range roots {
		batch, werr := walkOneScoped(r, opts)
		if werr != nil {
			return out, werr
		}
		for _, t := range batch {
			if _, ok := seen[t.Path]; ok {
				continue
			}
			seen[t.Path] = struct{}{}
			out = append(out, t)
			if opts.MaxFiles > 0 && len(out) > opts.MaxFiles {
				return out[:opts.MaxFiles], fmt.Errorf("%w: found >%d under %s", ErrTooManyFiles, opts.MaxFiles, root)
			}
		}
	}
	return out, nil
}

// resolveScopeRoots makes scope roots absolute and verifies they stay under
// `root` (after EvalSymlinks where possible). A path that escapes `root` is
// rejected to avoid surprising cross-tree scans.
func resolveScopeRoots(root string, scopes []string) ([]string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootAbs = resolved
	}
	if len(scopes) == 0 {
		return []string{rootAbs}, nil
	}
	var out []string
	for _, s := range scopes {
		if s == "" {
			continue
		}
		abs := s
		if !filepath.IsAbs(s) {
			abs = filepath.Join(rootAbs, s)
		}
		abs = filepath.Clean(abs)
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			abs = r
		}
		rel, rerr := filepath.Rel(rootAbs, abs)
		if rerr != nil || strings.HasPrefix(rel, "..") {
			return nil, fmt.Errorf("scope-root %q escapes target root %q", s, rootAbs)
		}
		if _, err := os.Stat(abs); err != nil {
			return nil, fmt.Errorf("scope-root %q: %w", s, err)
		}
		out = append(out, abs)
	}
	if len(out) == 0 {
		return []string{rootAbs}, nil
	}
	return out, nil
}

// walkOneScoped is the inner WalkDir loop for a single root. It applies the
// same filter semantics as Walk() so behavior is identical when ScopeRoots
// is unset.
//
//nolint:gocyclo // filter pipeline mirrors Walk(); flat is intentional.
func walkOneScoped(root string, opts WalkOptions) ([]types.FileTarget, error) {
	var targets []types.FileTarget
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if IsExcluded(p+"/", opts.Exclude) {
				return fs.SkipDir
			}
			return nil
		}
		if !opts.FollowSymlinks {
			if info, ierr := d.Info(); ierr == nil && info.Mode()&os.ModeSymlink != 0 {
				return nil
			}
		}
		if IsExcluded(p, opts.Exclude) {
			return nil
		}
		if len(opts.Include) > 0 {
			ok := false
			for _, pat := range opts.Include {
				if m, _ := filepath.Match(pat, filepath.Base(p)); m {
					ok = true
					break
				}
			}
			if !ok {
				return nil
			}
		}
		lang := LanguageOf(p)
		if lang == "" {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if opts.MaxBytes > 0 && info.Size() > int64(opts.MaxBytes) {
			return nil
		}
		b, rerr := os.ReadFile(p) //nolint:gosec // p comes from WalkDir under user-supplied root
		if rerr != nil {
			return nil
		}
		content := string(b)
		targets = append(targets, types.FileTarget{
			Path:     p,
			Language: lang,
			Content:  content,
			Lines:    strings.Count(content, "\n") + 1,
		})
		return nil
	})
	return targets, err
}
