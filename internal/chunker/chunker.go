// Package chunker provides AST-aware chunking with map-reduce support for
// files exceeding a configurable LOC budget.
package chunker

import (
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Options controls chunking.
type Options struct {
	MaxLines      int // soft cap per chunk
	OverlapLines  int // lines of overlap between sliding windows
	MapReduceLOC  int // files >= this LOC are split into chunks + a summary chunk
}

// Default returns reasonable defaults.
func Default() Options {
	return Options{MaxLines: 250, OverlapLines: 20, MapReduceLOC: 2000}
}

// Chunk a parsed file into one or more FileTarget entries. When the file is
// large (>= MapReduceLOC), an additional chunk index 0 is produced containing
// a structural "outline" (imports + function signatures) — this is the
// "reduce" stage's prompt context.
func Chunk(f *ast.FileAST, opts Options) []types.FileTarget {
	if f == nil {
		return nil
	}
	src := string(ast.FileSource(f))
	lines := strings.Split(src, "\n")
	loc := len(lines)

	chunks := chunkByLines(lines, opts)
	for i := range chunks {
		chunks[i].Path = f.Path
		chunks[i].Language = string(f.Language)
		chunks[i].ChunkTotal = len(chunks)
		chunks[i].ChunkIdx = i
	}

	if loc >= opts.MapReduceLOC && opts.MapReduceLOC > 0 {
		summary := outline(f, src)
		summaryTarget := types.FileTarget{
			Path:       f.Path,
			Language:   string(f.Language),
			Content:    summary,
			Lines:      strings.Count(summary, "\n") + 1,
			ChunkIdx:   -1,
			ChunkTotal: len(chunks),
			LineOffset: 0,
		}
		chunks = append([]types.FileTarget{summaryTarget}, chunks...)
	}
	return chunks
}

func chunkByLines(lines []string, opts Options) []types.FileTarget {
	if opts.MaxLines <= 0 {
		opts.MaxLines = 250
	}
	if len(lines) <= opts.MaxLines {
		return []types.FileTarget{{
			Content:    strings.Join(lines, "\n"),
			Lines:      len(lines),
			LineOffset: 0,
		}}
	}
	var out []types.FileTarget
	step := opts.MaxLines - opts.OverlapLines
	if step <= 0 {
		step = opts.MaxLines
	}
	for start := 0; start < len(lines); start += step {
		end := start + opts.MaxLines
		if end > len(lines) {
			end = len(lines)
		}
		out = append(out, types.FileTarget{
			Content:    strings.Join(lines[start:end], "\n"),
			Lines:      end - start,
			LineOffset: start,
		})
		if end == len(lines) {
			break
		}
	}
	return out
}

// outline returns a compact structural summary used for the reduce stage on
// very large files: imports + top-level signatures only.
func outline(f *ast.FileAST, src string) string {
	var b strings.Builder
	b.WriteString("// FILE OUTLINE (imports + top-level signatures)\n")
	for _, imp := range f.Imports {
		b.WriteString("import ")
		b.WriteString(imp.Path)
		if imp.Alias != "" {
			b.WriteString(" as ")
			b.WriteString(imp.Alias)
		}
		b.WriteString("\n")
	}
	lines := strings.Split(src, "\n")
	for _, s := range f.Symbols {
		if s.Kind != "function" && s.Kind != "method" && s.Kind != "class" {
			continue
		}
		idx := s.StartLine - 1
		if idx < 0 || idx >= len(lines) {
			continue
		}
		b.WriteString(strings.TrimSpace(lines[idx]))
		b.WriteString("  // ")
		b.WriteString(s.Kind)
		if s.Receiver != "" {
			b.WriteString(" on ")
			b.WriteString(s.Receiver)
		}
		b.WriteString("\n")
	}
	return b.String()
}
