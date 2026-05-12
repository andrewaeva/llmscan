package chunker

import (
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/tokens"
	"github.com/andrewaeva/llmscan/internal/types"
)

// AdaptiveOptions controls token-aware chunking. Sizes are in *tokens* rather
// than lines, so chunks behave consistently across languages with different
// densities (e.g. Go vs. Python). The chunker groups consecutive top-level
// symbols (functions, methods, classes, structs) until either the target is
// hit or the next symbol would overshoot the hard max.
type AdaptiveOptions struct {
	// TargetTokens is the preferred chunk size. The packer tries to reach
	// this value before cutting; it may exceed it by up to one symbol if
	// MaxTokens allows.
	TargetTokens int
	// MaxTokens is the absolute upper bound. Symbols that overshoot Max on
	// their own are emitted as a single oversize chunk (so we never split a
	// function mid-body) and Pack.Overflow downstream re-chunks them by line.
	MaxTokens int
	// MinTokens prevents tiny tail chunks: anything below this gets merged
	// into the previous chunk even if that pushes it past Target.
	MinTokens int
	// FallbackLines applies when AST has no symbols (config files, plain
	// text). Sliding window of N lines without overlap.
	FallbackLines int
}

// DefaultAdaptiveOptions targets 200K-context models (Claude Opus/Sonnet 4.x,
// GPT-5.x, Gemini 2.5 Pro). 8K target ≈ 700-1000 LOC of Go.
func DefaultAdaptiveOptions() AdaptiveOptions {
	return AdaptiveOptions{
		TargetTokens:  8000,
		MaxTokens:     16000,
		MinTokens:     500,
		FallbackLines: 400,
	}
}

// ChunkAdaptive splits f into token-budgeted, symbol-aware chunks. Behaviour:
//
//  1. Sort top-level symbols by start line.
//  2. Greedily pack adjacent symbols into a single chunk while running
//     token total stays below TargetTokens; stop early if adding the next
//     symbol would exceed MaxTokens.
//  3. Any source lines *between* covered symbols (imports, package decls,
//     vars) are attached to the chunk whose symbol comes after them; this
//     keeps each chunk a contiguous line range.
//  4. If f has no symbols, fall back to a sliding window by lines.
//  5. Each chunk gets ChunkIdx in [0, N) and ChunkTotal=N. LineOffset is
//     the absolute starting line index (0-based) into the original file.
//
// The function never mutates f.
func ChunkAdaptive(f *ast.FileAST, opts AdaptiveOptions) []types.FileTarget {
	if f == nil {
		return nil
	}
	opts = opts.normalize()
	src := string(ast.FileSource(f))
	lines := strings.Split(src, "\n")
	if len(lines) == 0 {
		return nil
	}

	// Symbols we care about for grouping: top-level callable / type defs.
	syms := topLevelSymbols(f)
	if len(syms) == 0 {
		return chunkAdaptiveByLines(lines, opts, f)
	}

	// Pack symbols → chunk boundaries (line ranges).
	bounds := packSymbols(syms, lines, opts)
	out := make([]types.FileTarget, 0, len(bounds))
	for i, b := range bounds {
		body := strings.Join(lines[b.start:b.end], "\n")
		out = append(out, types.FileTarget{
			Path:       f.Path,
			Language:   string(f.Language),
			Content:    body,
			Lines:      b.end - b.start,
			ChunkIdx:   i,
			LineOffset: b.start,
		})
	}
	for i := range out {
		out[i].ChunkTotal = len(out)
	}
	return out
}

func (o AdaptiveOptions) normalize() AdaptiveOptions {
	if o.TargetTokens <= 0 {
		o.TargetTokens = 8000
	}
	if o.MaxTokens <= 0 || o.MaxTokens < o.TargetTokens {
		o.MaxTokens = 2 * o.TargetTokens
	}
	if o.MinTokens <= 0 {
		o.MinTokens = 500
	}
	if o.FallbackLines <= 0 {
		o.FallbackLines = 400
	}
	return o
}

// topLevelSymbols returns symbols suitable for grouping, sorted by start line.
// Methods are included because in Go a long method file is the common case.
func topLevelSymbols(f *ast.FileAST) []*ast.Symbol {
	if f == nil {
		return nil
	}
	out := make([]*ast.Symbol, 0, len(f.Symbols))
	for i := range f.Symbols {
		s := &f.Symbols[i]
		switch s.Kind {
		case "function", "method", "class", "struct", "interface":
			if s.StartLine > 0 && s.EndLine >= s.StartLine {
				out = append(out, s)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].StartLine < out[j].StartLine })
	return out
}

type lineRange struct{ start, end int } // [start, end), 0-based line indices

// packSymbols greedily groups symbols into chunks.
//
// Algorithm:
//
//	curStart  = line of first byte not yet emitted (0-based)
//	curEnd    = candidate end of current chunk (exclusive)
//	for each symbol s in StartLine order:
//	  symEnd = s.EndLine
//	  // Lines between curEnd and symStart belong to current chunk too
//	  // (imports, package-level vars, comments between funcs).
//	  tentativeEnd = symEnd
//	  if tokens(curStart, tentativeEnd) <= Target:
//	      curEnd = tentativeEnd                        // keep packing
//	  else if curEnd == curStart:
//	      // First symbol already overshoots Target.
//	      // If it fits under Max, accept it as a single-symbol chunk;
//	      // otherwise still emit it whole (oversize chunk → contextpack
//	      // overflow will re-split it by line in the pipeline).
//	      curEnd = tentativeEnd
//	      flush(curEnd)
//	  else:
//	      flush(curEnd)
//	      curEnd = symEnd
//	flush(len(lines))                                  // tail
//	merge last chunk into previous when below MinTokens.
func packSymbols(syms []*ast.Symbol, lines []string, opts AdaptiveOptions) []lineRange {
	if len(syms) == 0 {
		return nil
	}
	var out []lineRange
	curStart, curEnd := 0, 0

	flush := func(end int) {
		if end <= curStart {
			return
		}
		if end > len(lines) {
			end = len(lines)
		}
		out = append(out, lineRange{start: curStart, end: end})
		curStart = end
		curEnd = end
	}

	for _, s := range syms {
		symEnd0 := s.EndLine // exclusive (1-based StartLine → 0-based start: EndLine ≈ exclusive end already)
		if symEnd0 > len(lines) {
			symEnd0 = len(lines)
		}
		if symEnd0 <= curEnd {
			// Symbol fully inside an already-emitted chunk or zero-width.
			continue
		}

		tentativeToks := tokens.Estimate(joinLines(lines, curStart, symEnd0))
		switch {
		case tentativeToks <= opts.TargetTokens:
			curEnd = symEnd0
		case curEnd == curStart:
			// First symbol of the chunk overshoots Target. Accept it
			// whole — splitting a function body is worse than an
			// oversize chunk (the overflow loop will re-split by
			// line later if needed).
			curEnd = symEnd0
			flush(curEnd)
		default:
			flush(curEnd)
			curEnd = symEnd0
		}
	}
	flush(len(lines))

	// Merge undersized last chunk into the previous one.
	if len(out) >= 2 {
		last := out[len(out)-1]
		lastTok := tokens.Estimate(joinLines(lines, last.start, last.end))
		if lastTok < opts.MinTokens {
			out[len(out)-2].end = last.end
			out = out[:len(out)-1]
		}
	}
	return out
}

func joinLines(lines []string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start >= end {
		return ""
	}
	return strings.Join(lines[start:end], "\n")
}

// chunkAdaptiveByLines is the fallback when the file has no top-level symbols
// (config, plain text, generated code). Token-aware sliding window without
// overlap — overlap is unnecessary because the contextpack will pull in
// adjacent code from the same file as siblings when needed.
func chunkAdaptiveByLines(lines []string, opts AdaptiveOptions, f *ast.FileAST) []types.FileTarget {
	if len(lines) == 0 {
		return nil
	}
	var out []types.FileTarget
	start := 0
	for start < len(lines) {
		end := start + opts.FallbackLines
		if end > len(lines) {
			end = len(lines)
		}
		body := strings.Join(lines[start:end], "\n")
		// Honour MaxTokens: shrink window if estimator says too large.
		for tokens.Estimate(body) > opts.MaxTokens && end-start > 16 {
			end = start + (end-start)*2/3
			body = strings.Join(lines[start:end], "\n")
		}
		out = append(out, types.FileTarget{
			Path:       f.Path,
			Language:   string(f.Language),
			Content:    body,
			Lines:      end - start,
			LineOffset: start,
		})
		if end == len(lines) {
			break
		}
		start = end
	}
	for i := range out {
		out[i].ChunkIdx = i
		out[i].ChunkTotal = len(out)
	}
	return out
}

// SplitInHalf takes one chunk and produces two roughly equal halves by line.
// Used by the pipeline overflow-feedback loop: when a Pack signals that the
// chunk alone eats too much budget, this is how we shrink without losing
// coverage. The split is a clean line cut, no AST awareness, so it works on
// any input the original chunker produced.
func SplitInHalf(c types.FileTarget) (types.FileTarget, types.FileTarget) {
	lines := strings.Split(c.Content, "\n")
	if len(lines) < 4 {
		return c, types.FileTarget{}
	}
	mid := len(lines) / 2
	left := types.FileTarget{
		Path:       c.Path,
		Language:   c.Language,
		Content:    strings.Join(lines[:mid], "\n"),
		Lines:      mid,
		LineOffset: c.LineOffset,
		ChunkIdx:   c.ChunkIdx,
		ChunkTotal: c.ChunkTotal,
	}
	right := types.FileTarget{
		Path:       c.Path,
		Language:   c.Language,
		Content:    strings.Join(lines[mid:], "\n"),
		Lines:      len(lines) - mid,
		LineOffset: c.LineOffset + mid,
		ChunkIdx:   c.ChunkIdx,
		ChunkTotal: c.ChunkTotal,
	}
	return left, right
}
