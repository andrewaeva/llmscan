package pipeline

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/chunker"
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
	cfg := contextpack.FromConfig(e.Cfg)
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
	state := newContextPackBuildState(len(queue))

	for round := 0; round < maxRounds && len(queue) > 0; round++ {
		next := make([]types.FileTarget, 0, len(queue)*2)
		for _, c := range queue {
			pack, hit := loadOrBuildContextPack(ctx, builder, cacheDB, cacheEnabled, c)
			if hit {
				state.cacheHits++
			}
			if shouldRechunkPack(pack, round, maxRounds, c) {
				// Split chunk and re-queue for next round.
				state.overflowCount++
				state.rechunks++
				left, right := chunker.SplitInHalf(c)
				next = append(next, left, right)
				e.logf("context-pack: overflow on %s:%d-%d (%s) → split",
					c.Path, c.LineOffset+1, c.LineOffset+c.Lines, pack.OverflowReason)
				continue
			}
			if pack.Overflow {
				state.overflowCount++
				e.logf("context-pack: overflow on %s:%d-%d (kept, max splits reached)",
					c.Path, c.LineOffset+1, c.LineOffset+c.Lines)
			}
			state.record(c, pack)
			e.prog().Inc("context-pack", 1)
		}
		queue = next
	}

	// Anything left in the queue after maxRounds: emit as-is, packs assembled
	// with overflow flag preserved so the operator sees in logs/stats.
	for _, c := range queue {
		pack := builder.Build(ctx, c)
		state.record(c, pack)
	}

	s.chunks = state.outChunks
	s.cpStats = types.ContextPackStats{
		Packs:            len(state.outChunks),
		SqueezedChunks:   state.totalSqueezed,
		DroppedFragments: state.totalDropped,
		Rechunks:         state.rechunks,
		CacheHits:        state.cacheHits,
	}
	if n := len(state.outChunks); n > 0 {
		s.cpStats.AvgFragments = float64(state.totalFragments) / float64(n)
		s.cpStats.AvgTokensSent = float64(state.totalTokensSent) / float64(n)
		s.cpStats.OverflowRate = float64(state.overflowCount) / float64(n+state.overflowCount)
		s.cpStats.P95TokensSent = percentileInt(state.tokenSamples, 95)
	}
	s.report.Stats.ContextPack = &s.cpStats

	// Stash on scanContext (will be set during dag-build).
	s.scanCtx.packsByChunkKey = state.outPacks

	e.prog().Done("context-pack")
	e.logf("context-pack: %d packs, avg frags=%.1f avg tokens=%.0f overflow=%d rechunks=%d cache_hits=%d",
		len(state.outChunks), s.cpStats.AvgFragments, s.cpStats.AvgTokensSent,
		state.overflowCount, state.rechunks, state.cacheHits)
	return nil
}

type contextPackBuildState struct {
	outChunks []types.FileTarget
	outPacks  map[string]*contextpack.Pack

	totalFragments  int
	totalTokensSent int
	tokenSamples    []int
	overflowCount   int
	rechunks        int
	cacheHits       int
	totalSqueezed   int
	totalDropped    int
}

func newContextPackBuildState(capacity int) *contextPackBuildState {
	return &contextPackBuildState{
		outChunks: make([]types.FileTarget, 0, capacity),
		outPacks:  make(map[string]*contextpack.Pack, capacity),
	}
}

func (s *contextPackBuildState) record(c types.FileTarget, pack contextpack.Pack) {
	s.outChunks = append(s.outChunks, c)
	p := pack
	s.outPacks[chunkPackKey(c)] = &p
	s.totalFragments += len(pack.Fragments)
	s.totalTokensSent += pack.UsedTokens
	s.tokenSamples = append(s.tokenSamples, pack.UsedTokens)
	s.totalSqueezed += pack.Squeezed
	s.totalDropped += pack.Dropped
}

func shouldRechunkPack(pack contextpack.Pack, round, maxRounds int, c types.FileTarget) bool {
	return pack.Overflow && round+1 < maxRounds && c.Lines > 4
}

func loadOrBuildContextPack(
	ctx context.Context,
	builder *contextpack.Builder,
	cacheDB interface {
		GetContextPack(string) ([]byte, bool)
		PutContextPack(string, []byte) error
	},
	cacheEnabled bool,
	c types.FileTarget,
) (contextpack.Pack, bool) {
	pack, hit := lookupPackFromCache(builder, cacheDB, cacheEnabled, c)
	if hit {
		return pack, true
	}
	pack = builder.Build(ctx, c)
	if cacheEnabled && !pack.Overflow {
		if payload, err := contextpack.EncodePack(pack); err == nil {
			_ = cacheDB.PutContextPack(builder.CacheKeyFor(c), payload)
		}
	}
	return pack, false
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
