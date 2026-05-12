package util

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/andrewaeva/llmscan/internal/types"
)

// codeExtensions maps file extension -> coarse language label.
var codeExtensions = map[string]string{
	".go":         "go",
	".py":         "python",
	".js":         "javascript",
	".jsx":        "javascript",
	".ts":         "typescript",
	".tsx":        "typescript",
	".java":       "java",
	".kt":         "kotlin",
	".rb":         "ruby",
	".php":        "php",
	".rs":         "rust",
	".c":          "c",
	".h":          "c",
	".cc":         "cpp",
	".cpp":        "cpp",
	".hpp":        "cpp",
	".cs":         "csharp",
	".scala":      "scala",
	".swift":      "swift",
	".sh":         "shell",
	".bash":       "shell",
	".zsh":        "shell",
	".sql":        "sql",
	".tf":         "terraform",
	".yml":        "yaml",
	".yaml":       "yaml",
	".json":       "json",
	".toml":       "toml",
	".xml":        "xml",
	".html":       "html",
	".dockerfile": "dockerfile",
}

// LanguageOf returns a language label for a file path, or "" if unknown.
func LanguageOf(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "dockerfile" {
		return "dockerfile"
	}
	ext := strings.ToLower(filepath.Ext(path))
	return codeExtensions[ext]
}

// IsExcluded reports whether path matches any exclude pattern (substring or glob on basename).
func IsExcluded(path string, patterns []string) bool {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if strings.Contains(path, p) {
			return true
		}
		if m, _ := filepath.Match(p, filepath.Base(path)); m {
			return true
		}
	}
	return false
}

// Walk discovers code files under root, applying include/exclude/maxBytes filters.
// `include` is matched on the file path with filepath.Match against the basename; empty means all.
//
//nolint:gocyclo // filter pipeline with include/exclude/size/symlink branches
func Walk(root string, include, exclude []string, maxBytes int, followSymlinks bool) ([]types.FileTarget, error) {
	var targets []types.FileTarget
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // ignore permission errors etc.
		}
		if d.IsDir() {
			if IsExcluded(p+"/", exclude) {
				return fs.SkipDir
			}
			return nil
		}
		if !followSymlinks {
			if info, ierr := d.Info(); ierr == nil && info.Mode()&os.ModeSymlink != 0 {
				return nil
			}
		}
		if IsExcluded(p, exclude) {
			return nil
		}
		if len(include) > 0 {
			ok := false
			for _, pat := range include {
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
		if maxBytes > 0 && info.Size() > int64(maxBytes) {
			return nil
		}
		b, rerr := os.ReadFile(p) //nolint:gosec // p comes from WalkDir under user-supplied root; reading is intentional
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

