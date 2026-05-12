// Package contextpack assembles, for a given code chunk, the transitive closure
// of *logical* dependencies — callees, callers, used types, sanitizers, similar
// code from the project — and renders them as a single prompt-ready bundle
// inside a hard token budget.
//
// Rationale
//
//	The LLM-based scanner is only as good as the context it sees. Sending a
//	chunk in isolation forces the model to guess about callees, types, and
//	taint flow. By preloading dependencies we move the model from "guess" to
//	"verify against the actual code", which collapses both false positives
//	(model assumed a sanitizer existed) and false negatives (model could not
//	see the sink at all).
//
// Design overview
//
//   - One Builder per scan, holding immutable indices (AST, call graph,
//     depgraph, watchlist, RAG index). Build() is safe for concurrent use.
//   - Fragments are collected from multiple sources, each tagged with Kind,
//     Reason, and Priority (chunk=0, direct=1, transitive=2, ...).
//   - Deduplication is by (file, overlapping line range): two fragments that
//     cover the same source code are merged into one with the lowest priority
//     and the union of reasons.
//   - Budgeting is priority-greedy: lower priority first; ties broken by
//     fewest tokens; if a fragment is too large to fit but is at priority<=1,
//     it is *squeezed* (head + middle elision marker + tail) instead of being
//     dropped, so that the chunk itself never gets cut.
//   - The final pack is cache-friendly: identical (chunk_hash, cfg_hash) maps
//     to a deterministic byte-stable Render() output.
//
// What is NOT here
//
//	The package does not call any LLM and does not parse code. It depends on
//	the existing AST, callgraph, depgraph, RAG, and watchlist packages and
//	stitches them together. Per-language quirks live in those packages.
package contextpack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/tokens"
	"github.com/andrewaeva/llmscan/internal/types"
)

// FragmentKind classifies why a piece of code was included.
type FragmentKind string

const (
	KindChunk     FragmentKind = "chunk"     // the code being analysed
	KindCallee    FragmentKind = "callee"    // function called (in)directly from chunk
	KindCaller    FragmentKind = "caller"    // function calling into chunk
	KindType      FragmentKind = "type"      // struct/interface/class used by chunk
	KindSanitizer FragmentKind = "sanitizer" // sanitizer-like function reachable in scope
	KindSibling   FragmentKind = "sibling"   // adjacent symbol in the same file
	KindRAG       FragmentKind = "rag"       // semantically similar code
	KindConst     FragmentKind = "const"     // referenced constant / config
)

// Fragment is one self-contained piece of code attached to a chunk.
type Fragment struct {
	Kind     FragmentKind `json:"kind"`
	Reason   string       `json:"reason"`
	File     string       `json:"file"`
	Symbol   string       `json:"symbol,omitempty"`
	Start    int          `json:"start_line"`
	End      int          `json:"end_line"`
	Code     string       `json:"code"`
	Priority int          `json:"priority"` // lower = more important
	Tokens   int          `json:"tokens"`
	Squeezed bool         `json:"squeezed,omitempty"`
}

// Pack is the full assembled bundle for one chunk.
type Pack struct {
	Chunk         Fragment   `json:"chunk"`                    // priority=0, never dropped
	Fragments     []Fragment `json:"fragments"`                // all other code, in render order
	Budget        int        `json:"budget"`                   // hard token cap that was applied
	UsedTokens    int        `json:"used_tokens"`              // sum of Fragment.Tokens + Chunk.Tokens
	Dropped       int        `json:"dropped"`                  // candidates that did not fit at all
	Squeezed      int        `json:"squeezed"`                 // candidates included but truncated
	CacheKey      string     `json:"cache_key"`                // sha256(chunk_hash || cfg_hash)
	Truncated     bool       `json:"truncated"`                // true if any code was dropped or squeezed

	// Overflow signals that even after squeezing+dropping, the chunk alone
	// is too large to leave useful room for dependencies inside Budget. The
	// pipeline reads this and re-chunks the input. A chunk is considered
	// overflowing when Chunk.Tokens >= Budget * OverflowRatio.
	Overflow         bool    `json:"overflow"`
	OverflowReason   string  `json:"overflow_reason,omitempty"`
	ChunkShareOfBudget float64 `json:"chunk_share_of_budget"` // 0..1+

	candidatesAll []Fragment // pre-budget pool, kept for diagnostics
}

// Config controls what the Builder collects and how aggressively.
//
// The zero value is deliberately useless; callers should construct it from
// DefaultConfig() and a Level preset, then override individual fields. YAML
// mapping lives in internal/config; this package only sees the resolved view.
type Config struct {
	// BudgetTokens is the hard upper bound on the rendered prompt size,
	// chunk-included. Squeezing and dropping enforce it.
	BudgetTokens int

	// CalleesHops controls how many transitive call-graph hops outward are
	// chased. 0 disables, 1 = direct callees only.
	CalleesHops int
	// CalleesMax caps the absolute number of callee fragments after hops.
	CalleesMax int

	// CallersHops mirrors CalleesHops, but traversing incoming edges.
	CallersHops int
	CallersMax  int

	// IncludeTypes adds struct/interface/class definitions referenced by name
	// inside the chunk body.
	IncludeTypes bool
	TypesMax     int

	// IncludeSanitizers adds functions in the same module whose names match the
	// watchlist's sanitizer regexes. Useful for the LLM to rule out FPs.
	IncludeSanitizers bool
	SanitizersMax     int

	// IncludeSiblings adds neighbouring top-level symbols in the same file,
	// closest first by line distance.
	IncludeSiblings bool
	SiblingsMax     int

	// RAGTopK adds K semantically similar chunks via the embedding index.
	// 0 disables. Requires Builder.RAG to be set.
	RAGTopK int

	// IncludeConsts scans chunk for ALL_CAPS identifiers and pulls their
	// definitions from the same file or imported files.
	IncludeConsts bool
	ConstsMax     int

	// SqueezeHeadLines / SqueezeTailLines control how oversized fragments are
	// truncated when budget is tight. The middle is replaced with a marker.
	SqueezeHeadLines int
	SqueezeTailLines int

	// OverflowRatio is the share of the budget the chunk itself is allowed to
	// occupy before Pack.Overflow is set. Default 0.6 — leaves 40% of the
	// budget for dependencies. When the pipeline sees Overflow=true it splits
	// the chunk and rebuilds.
	OverflowRatio float64

	// Level is a free-form label used in CacheKey + diagnostics so that two
	// presets with the same numeric fields still produce distinct cache keys
	// if the operator names them differently (e.g. for A/B comparisons).
	Level string
}

// DefaultConfig returns "balanced": callees hops=2, callers hops=1, types and
// sanitizers on, RAG off, siblings off. Tuned for Claude/Opus-class models
// with a 200K context and ~80K pack budget.
func DefaultConfig() Config {
	return Config{
		BudgetTokens:      80000,
		CalleesHops:       2,
		CalleesMax:        40,
		CallersHops:       1,
		CallersMax:        12,
		IncludeTypes:      true,
		TypesMax:          20,
		IncludeSanitizers: true,
		SanitizersMax:     10,
		IncludeSiblings:   false,
		SiblingsMax:       4,
		RAGTopK:           0,
		IncludeConsts:     false,
		ConstsMax:         15,
		SqueezeHeadLines:  40,
		SqueezeTailLines:  20,
		OverflowRatio:     0.6,
		Level:             "balanced",
	}
}

// AggressiveConfig adds RAG (k=5), siblings, and consts on top of balanced.
func AggressiveConfig() Config {
	c := DefaultConfig()
	c.RAGTopK = 5
	c.IncludeSiblings = true
	c.IncludeConsts = true
	c.Level = "aggressive"
	return c
}

// ExtremeConfig pushes hops further and increases caps; budget grows to 120K.
// Use only with 200K+ context models.
func ExtremeConfig() Config {
	c := AggressiveConfig()
	c.BudgetTokens = 120000
	c.CalleesHops = 3
	c.CalleesMax = 80
	c.CallersHops = 2
	c.CallersMax = 24
	c.TypesMax = 40
	c.SiblingsMax = 12
	c.OverflowRatio = 0.55
	c.Level = "extreme"
	return c
}

// MinimalConfig approximates the legacy symbol-expansion behaviour: direct
// callees only, no callers, no types beyond definitions actually referenced.
func MinimalConfig() Config {
	return Config{
		BudgetTokens:     40000,
		CalleesHops:      1,
		CalleesMax:       12,
		CallersHops:      0,
		CallersMax:       0,
		IncludeTypes:     false,
		IncludeSiblings:  false,
		RAGTopK:          0,
		SqueezeHeadLines: 30,
		SqueezeTailLines: 15,
		OverflowRatio:    0.7,
		Level:            "minimal",
	}
}

// hash returns a deterministic stable hash of the config.
func (c Config) hash() string {
	h := sha256.New()
	fmt.Fprintf(h, "v1|budget=%d|chops=%d|cmax=%d|callhops=%d|callmax=%d|"+
		"types=%v/%d|san=%v/%d|sib=%v/%d|rag=%d|const=%v/%d|sq=%d/%d|lvl=%s",
		c.BudgetTokens, c.CalleesHops, c.CalleesMax, c.CallersHops, c.CallersMax,
		c.IncludeTypes, c.TypesMax, c.IncludeSanitizers, c.SanitizersMax,
		c.IncludeSiblings, c.SiblingsMax, c.RAGTopK,
		c.IncludeConsts, c.ConstsMax, c.SqueezeHeadLines, c.SqueezeTailLines, c.Level)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Validate enforces invariants. Called once at engine startup.
func (c Config) Validate() error {
	if c.BudgetTokens < 1000 {
		return fmt.Errorf("contextpack: budget_tokens=%d must be >= 1000", c.BudgetTokens)
	}
	if c.CalleesHops < 0 || c.CallersHops < 0 {
		return fmt.Errorf("contextpack: hops must be >= 0")
	}
	if c.CalleesMax < 0 || c.CallersMax < 0 || c.TypesMax < 0 ||
		c.SanitizersMax < 0 || c.SiblingsMax < 0 || c.RAGTopK < 0 || c.ConstsMax < 0 {
		return fmt.Errorf("contextpack: *Max counters must be >= 0")
	}
	if c.SqueezeHeadLines < 5 || c.SqueezeTailLines < 5 {
		return fmt.Errorf("contextpack: squeeze head/tail lines must be >= 5")
	}
	if c.OverflowRatio < 0.1 || c.OverflowRatio > 1 {
		return fmt.Errorf("contextpack: overflow_ratio=%v must be in [0.1, 1]", c.OverflowRatio)
	}
	return nil
}

// SanitizerMatcher decides whether a function name looks like a sanitizer for
// a given language. Implementations live in internal/watchlist; this is a
// minimal interface so the contextpack package stays acyclic.
type SanitizerMatcher interface {
	IsSanitizer(language, name string) bool
}

// Builder owns the immutable indices needed to assemble packs. Construct one
// per scan after AST, depgraph, and call graph are ready.
type Builder struct {
	Cfg        Config
	ASTByPath  map[string]*ast.FileAST
	CG         *callgraph.CallGraph
	Deps       *depgraph.Graph
	RAG        *rag.Index // optional; nil disables RAG
	Sanitizers SanitizerMatcher
}

// New returns a ready-to-use builder. The caller may set RAG/Sanitizers post
// hoc, but Cfg, ASTByPath, CG, and Deps must be non-nil.
func New(cfg Config, astByPath map[string]*ast.FileAST, cg *callgraph.CallGraph, deps *depgraph.Graph) *Builder {
	return &Builder{
		Cfg:       cfg,
		ASTByPath: astByPath,
		CG:        cg,
		Deps:      deps,
	}
}

// Build assembles the context pack for one chunk. Safe for concurrent use as
// long as none of the underlying indices are being mutated.
//
// If the chunk's own tokens exceed BudgetTokens * OverflowRatio, the pack is
// returned with Overflow=true and the pipeline is expected to split the chunk
// in two and rebuild. Dependencies are still collected so the operator can
// inspect *what would have been included*, but they may not all fit.
func (b *Builder) Build(ctx context.Context, c types.FileTarget) Pack {
	chunkFrag := b.chunkFragment(c)
	pack := Pack{
		Chunk:    chunkFrag,
		Budget:   b.Cfg.BudgetTokens,
		CacheKey: b.cacheKey(c),
	}
	pack.ChunkShareOfBudget = float64(chunkFrag.Tokens) / float64(b.Cfg.BudgetTokens)

	// Early overflow signal: if the chunk itself eats too much of the budget,
	// flag it so the pipeline re-chunks. We still collect dependencies — the
	// caller may decide to send the pack as-is for very small budgets.
	ratio := b.Cfg.OverflowRatio
	if ratio <= 0 {
		ratio = 0.6
	}
	if chunkFrag.Tokens > int(float64(b.Cfg.BudgetTokens)*ratio) {
		pack.Overflow = true
		pack.OverflowReason = fmt.Sprintf(
			"chunk_tokens=%d exceeds %.0f%% of budget=%d (cap=%d)",
			chunkFrag.Tokens, ratio*100, b.Cfg.BudgetTokens,
			int(float64(b.Cfg.BudgetTokens)*ratio))
	}

	// Used budget already includes the chunk itself, which is sacrosanct.
	used := chunkFrag.Tokens

	// 1) Collect candidates from every enabled source.
	var cands []Fragment
	cands = append(cands, b.collectCallees(c)...)
	cands = append(cands, b.collectCallers(c)...)
	if b.Cfg.IncludeTypes {
		cands = append(cands, b.collectTypes(c)...)
	}
	if b.Cfg.IncludeSanitizers && b.Sanitizers != nil {
		cands = append(cands, b.collectSanitizers(c)...)
	}
	if b.Cfg.IncludeSiblings {
		cands = append(cands, b.collectSiblings(c)...)
	}
	if b.Cfg.RAGTopK > 0 && b.RAG != nil {
		cands = append(cands, b.collectRAG(ctx, c)...)
	}
	if b.Cfg.IncludeConsts {
		cands = append(cands, b.collectConsts(c)...)
	}

	// 2) Deduplicate by overlapping (file, range). Merges priorities + reasons.
	cands = dedupe(cands, chunkFrag)
	pack.candidatesAll = cands

	// 3) Priority-greedy admission within the remaining budget.
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].Priority != cands[j].Priority {
			return cands[i].Priority < cands[j].Priority
		}
		return cands[i].Tokens < cands[j].Tokens
	})
	for _, f := range cands {
		left := b.Cfg.BudgetTokens - used
		if left <= 100 {
			pack.Dropped++
			continue
		}
		if f.Tokens <= left {
			pack.Fragments = append(pack.Fragments, f)
			used += f.Tokens
			continue
		}
		// Too big — squeeze if it's important (priority <=2) and there's a
		// non-trivial budget remaining; otherwise drop.
		if f.Priority <= 2 && left >= 400 {
			sq := b.squeeze(f, left)
			pack.Fragments = append(pack.Fragments, sq)
			pack.Squeezed++
			used += sq.Tokens
			continue
		}
		pack.Dropped++
	}

	pack.UsedTokens = used
	pack.Truncated = pack.Dropped > 0 || pack.Squeezed > 0
	return pack
}

// chunkFragment wraps the chunk itself as a Fragment with priority 0.
func (b *Builder) chunkFragment(c types.FileTarget) Fragment {
	end := c.LineOffset + c.Lines
	if end < c.LineOffset+1 {
		end = c.LineOffset + 1
	}
	return Fragment{
		Kind:     KindChunk,
		Reason:   "primary chunk under analysis",
		File:     c.Path,
		Start:    c.LineOffset + 1,
		End:      end,
		Code:     c.Content,
		Priority: 0,
		Tokens:   tokens.Estimate(c.Content),
	}
}

// cacheKey is a stable id for (chunk content, cfg). Caller-side caches can use
// it as a primary key.
func (b *Builder) cacheKey(c types.FileTarget) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%d\x00%d\x00%d\x00", c.Path, c.LineOffset, c.Lines, c.ChunkIdx)
	h.Write([]byte(c.Content))
	h.Write([]byte("\x00cfg=" + b.Cfg.hash()))
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// Render returns the human-readable, prompt-ready textual representation of
// the pack. The format is deterministic so it is safe to cache.
func (p Pack) Render() string {
	var b strings.Builder
	b.Grow(p.UsedTokens * 4)

	// Chunk first — always present, always full.
	fmt.Fprintf(&b, "<<<MAIN CHUNK %s:%d-%d>>>\n", p.Chunk.File, p.Chunk.Start, p.Chunk.End)
	b.WriteString(p.Chunk.Code)
	if !strings.HasSuffix(p.Chunk.Code, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("<<<END MAIN CHUNK>>>\n")

	if len(p.Fragments) == 0 {
		return b.String()
	}

	b.WriteString("\n// ====================================================\n")
	b.WriteString("// Auto-included dependencies (read-only context)\n")
	b.WriteString("// ====================================================\n")
	b.WriteString("// You see these because they are logically related to the\n")
	b.WriteString("// chunk: callees, callers, types, sanitizers, or similar\n")
	b.WriteString("// code. Use them to verify hypotheses about taint flow,\n")
	b.WriteString("// sanitization, and type assumptions BEFORE flagging a\n")
	b.WriteString("// finding. If a dependency rules out the vulnerability,\n")
	b.WriteString("// say so explicitly and cite file:line.\n")
	b.WriteString("// ====================================================\n\n")

	// Group fragments by Kind for readability.
	byKind := map[FragmentKind][]Fragment{}
	order := []FragmentKind{
		KindCallee, KindCaller, KindType, KindSanitizer,
		KindConst, KindSibling, KindRAG,
	}
	for _, f := range p.Fragments {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	for _, k := range order {
		frags := byKind[k]
		if len(frags) == 0 {
			continue
		}
		fmt.Fprintf(&b, "// ---- %s (%d) ----\n", k, len(frags))
		for _, f := range frags {
			tag := ""
			if f.Squeezed {
				tag = " [squeezed]"
			}
			fmt.Fprintf(&b, "// %s @ %s:%d-%d — %s%s\n",
				symbolOrFile(f), f.File, f.Start, f.End, f.Reason, tag)
			b.WriteString(f.Code)
			if !strings.HasSuffix(f.Code, "\n") {
				b.WriteByte('\n')
			}
			b.WriteByte('\n')
		}
	}
	if p.Dropped > 0 || p.Squeezed > 0 {
		fmt.Fprintf(&b, "// [pack: %d fragments squeezed, %d dropped to fit budget=%d tokens]\n",
			p.Squeezed, p.Dropped, p.Budget)
	}
	return b.String()
}

func symbolOrFile(f Fragment) string {
	if f.Symbol != "" {
		return f.Symbol
	}
	return "(anonymous)"
}

// CacheKeyFor returns the cache key for a chunk under this builder's config.
// Exposed so the pipeline can persist packs across runs.
func (b *Builder) CacheKeyFor(c types.FileTarget) string { return b.cacheKey(c) }

// EncodePack serializes a Pack to a stable JSON byte slice for caching.
func EncodePack(p Pack) ([]byte, error) { return json.Marshal(p) }

// DecodePack restores a Pack from EncodePack output.
func DecodePack(b []byte) (Pack, error) {
	var p Pack
	if err := json.Unmarshal(b, &p); err != nil {
		return Pack{}, err
	}
	return p, nil
}
