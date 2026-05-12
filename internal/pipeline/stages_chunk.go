package pipeline

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/chunker"
	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/contextpack"
	"github.com/andrewaeva/llmscan/internal/types"
)

// stageChunk splits prioritized files into per-symbol adaptive chunks.
// When AST is unavailable (binary, parse failure) the whole file is emitted
// as a single chunk so the file still reaches scanners.
func stageChunk(_ context.Context, e *Engine, s *runState) error {
	s.prioritized = applyPlan(s.files, s.plan)
	opts := chunker.AdaptiveOptions{
		TargetTokens:  e.Cfg.Scan.Chunk.TargetTokens,
		MaxTokens:     e.Cfg.Scan.Chunk.MaxTokens,
		MinTokens:     e.Cfg.Scan.Chunk.MinTokens,
		FallbackLines: e.Cfg.Scan.Chunk.FallbackLines,
	}
	var chunks []types.FileTarget
	for _, f := range s.prioritized {
		fa := s.astByPath[f.Path]
		if fa == nil {
			chunks = append(chunks, wholeFileChunk(f))
			continue
		}
		adaptive := chunker.ChunkAdaptive(fa, opts)
		if len(adaptive) == 0 {
			chunks = append(chunks, wholeFileChunk(f))
			continue
		}
		chunks = append(chunks, adaptive...)
	}
	e.logf("chunker: adaptive (target=%d max=%d min=%d) → %d chunks across %d files",
		opts.TargetTokens, opts.MaxTokens, opts.MinTokens, len(chunks), len(s.prioritized))
	s.chunks = chunks
	return nil
}

// wholeFileChunk turns a single file into a single-chunk FileTarget.
func wholeFileChunk(f types.FileTarget) types.FileTarget {
	out := f
	out.ChunkIdx = 0
	out.LineOffset = 0
	if out.Lines == 0 {
		out.Lines = strings.Count(f.Content, "\n") + 1
	}
	return out
}

// stageBuildContextPacks assembles a contextpack.Pack for each chunk and
// implements the overflow feedback loop: when a chunk's pack signals
// Overflow=true (chunk_tokens > budget * OverflowRatio), the chunk is split
// in half and packs are rebuilt for each half. The loop is bounded to avoid
// pathological re-splitting (max 4 rounds).
func stageBuildContextPacks(ctx context.Context, e *Engine, s *runState) error {
	cfg := buildContextpackConfig(e.Cfg)
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("context-pack: invalid config: %w", err)
	}
	builder := contextpack.New(cfg, s.astByPath, s.cg, s.graph)
	if s.index != nil && cfg.RAGTopK > 0 {
		builder.RAG = s.index
	}
	s.cpBuilder = builder

	e.prog().Stage("context-pack", len(s.chunks))

	const maxRounds = 4
	cacheDB := s.cacheDB
	cacheEnabled := e.Cfg.Scan.Context.Cache && cacheDB != nil

	queue := append([]types.FileTarget(nil), s.chunks...)
	outChunks := make([]types.FileTarget, 0, len(queue))
	outPacks := make(map[string]*contextpack.Pack, len(queue))

	var (
		totalFragments  int
		totalTokensSent int
		tokenSamples    []int
		overflowCount   int
		rechunks        int
		cacheHits       int
		totalSqueezed   int
		totalDropped    int
	)

	for round := 0; round < maxRounds && len(queue) > 0; round++ {
		next := queue[:0]
		for _, c := range queue {
			pack, hit := lookupPackFromCache(builder, cacheDB, cacheEnabled, c)
			if hit {
				cacheHits++
			} else {
				pack = builder.Build(ctx, c)
				if cacheEnabled && !pack.Overflow {
					if payload, err := contextpack.EncodePack(pack); err == nil {
						_ = cacheDB.PutContextPack(builder.CacheKeyFor(c), payload)
					}
				}
			}

			if pack.Overflow && round+1 < maxRounds && c.Lines > 4 {
				// Split chunk and re-queue for next round.
				overflowCount++
				rechunks++
				left, right := chunker.SplitInHalf(c)
				next = append(next, left, right)
				e.logf("context-pack: overflow on %s:%d-%d (%s) → split",
					c.Path, c.LineOffset+1, c.LineOffset+c.Lines, pack.OverflowReason)
				continue
			}
			if pack.Overflow {
				overflowCount++
				e.logf("context-pack: overflow on %s:%d-%d (kept, max splits reached)",
					c.Path, c.LineOffset+1, c.LineOffset+c.Lines)
			}
			outChunks = append(outChunks, c)
			p := pack
			outPacks[chunkPackKey(c)] = &p
			totalFragments += len(pack.Fragments)
			totalTokensSent += pack.UsedTokens
			tokenSamples = append(tokenSamples, pack.UsedTokens)
			totalSqueezed += pack.Squeezed
			totalDropped += pack.Dropped
			e.prog().Inc("context-pack", 1)
		}
		queue = next
	}

	// Anything left in the queue after maxRounds: emit as-is, packs assembled
	// with overflow flag preserved so the operator sees in logs/stats.
	for _, c := range queue {
		pack := builder.Build(ctx, c)
		outChunks = append(outChunks, c)
		p := pack
		outPacks[chunkPackKey(c)] = &p
		totalFragments += len(pack.Fragments)
		totalTokensSent += pack.UsedTokens
		tokenSamples = append(tokenSamples, pack.UsedTokens)
		totalSqueezed += pack.Squeezed
		totalDropped += pack.Dropped
	}

	s.chunks = outChunks
	s.cpStats = types.ContextPackStats{
		Packs:            len(outChunks),
		SqueezedChunks:   totalSqueezed,
		DroppedFragments: totalDropped,
		Rechunks:         rechunks,
		CacheHits:        cacheHits,
	}
	if n := len(outChunks); n > 0 {
		s.cpStats.AvgFragments = float64(totalFragments) / float64(n)
		s.cpStats.AvgTokensSent = float64(totalTokensSent) / float64(n)
		s.cpStats.OverflowRate = float64(overflowCount) / float64(n+overflowCount)
		s.cpStats.P95TokensSent = percentileInt(tokenSamples, 95)
	}
	s.report.Stats.ContextPack = &s.cpStats

	// Stash on scanContext (will be set during dag-build).
	s.scanCtx.packsByChunkKey = outPacks

	e.prog().Done("context-pack")
	e.logf("context-pack: %d packs, avg frags=%.1f avg tokens=%.0f overflow=%d rechunks=%d cache_hits=%d",
		len(outChunks), s.cpStats.AvgFragments, s.cpStats.AvgTokensSent,
		overflowCount, rechunks, cacheHits)
	return nil
}

// lookupPackFromCache tries to fetch a previously-encoded pack from the cache.
// Returns (pack, true) on hit, (zero, false) otherwise.
func lookupPackFromCache(b *contextpack.Builder, cacheDB interface {
	GetContextPack(string) ([]byte, bool)
}, enabled bool, c types.FileTarget) (contextpack.Pack, bool) {
	if !enabled {
		return contextpack.Pack{}, false
	}
	payload, ok := cacheDB.GetContextPack(b.CacheKeyFor(c))
	if !ok {
		return contextpack.Pack{}, false
	}
	p, err := contextpack.DecodePack(payload)
	if err != nil {
		return contextpack.Pack{}, false
	}
	return p, true
}

// buildContextpackConfig resolves the runtime ContextPack config from cfg.
// Precedence: level preset → AutoContextBudget → per-field overrides.
func buildContextpackConfig(c config.Config) contextpack.Config {
	var base contextpack.Config
	switch strings.ToLower(c.Scan.Context.Level) {
	case "minimal":
		base = contextpack.MinimalConfig()
	case "aggressive":
		base = contextpack.AggressiveConfig()
	case "extreme":
		base = contextpack.ExtremeConfig()
	default:
		base = contextpack.DefaultConfig()
	}
	if b := c.AutoContextBudget(""); b > 0 {
		base.BudgetTokens = b
	}
	cc := c.Scan.Context
	if cc.CalleesHops > 0 {
		base.CalleesHops = cc.CalleesHops
	}
	if cc.CalleesMax > 0 {
		base.CalleesMax = cc.CalleesMax
	}
	if cc.CallersHops > 0 {
		base.CallersHops = cc.CallersHops
	}
	if cc.CallersMax > 0 {
		base.CallersMax = cc.CallersMax
	}
	if cc.IncludeTypes != nil {
		base.IncludeTypes = *cc.IncludeTypes
	}
	if cc.TypesMax > 0 {
		base.TypesMax = cc.TypesMax
	}
	if cc.IncludeSanitizers != nil {
		base.IncludeSanitizers = *cc.IncludeSanitizers
	}
	if cc.SanitizersMax > 0 {
		base.SanitizersMax = cc.SanitizersMax
	}
	if cc.IncludeSiblings != nil {
		base.IncludeSiblings = *cc.IncludeSiblings
	}
	if cc.SiblingsMax > 0 {
		base.SiblingsMax = cc.SiblingsMax
	}
	if cc.RAGTopK > 0 {
		base.RAGTopK = cc.RAGTopK
	}
	if cc.IncludeConsts != nil {
		base.IncludeConsts = *cc.IncludeConsts
	}
	if cc.ConstsMax > 0 {
		base.ConstsMax = cc.ConstsMax
	}
	if cc.SqueezeHeadLines > 0 {
		base.SqueezeHeadLines = cc.SqueezeHeadLines
	}
	if cc.SqueezeTailLines > 0 {
		base.SqueezeTailLines = cc.SqueezeTailLines
	}
	if cc.OverflowRatio > 0 {
		base.OverflowRatio = cc.OverflowRatio
	}
	return base
}

// percentileInt returns the (approximate) p-th percentile of xs (0<p<100).
func percentileInt(xs []int, p int) int {
	if len(xs) == 0 {
		return 0
	}
	copyXs := append([]int(nil), xs...)
	sort.Ints(copyXs)
	idx := (p * (len(copyXs) - 1)) / 100
	if idx < 0 {
		idx = 0
	}
	if idx >= len(copyXs) {
		idx = len(copyXs) - 1
	}
	return copyXs[idx]
}
