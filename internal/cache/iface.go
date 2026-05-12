package cache

// Cache is the subset of *DB that the pipeline depends on.
//
// Defining this interface lets pipeline code (and other consumers) accept any
// implementation — including in-memory fakes for tests — instead of being
// hard-wired to the SQLite-backed *DB. *DB satisfies Cache by construction.
type Cache interface {
	// Path returns a human-readable identifier for the storage backend (e.g.
	// the SQLite file path). Used in logs only.
	Path() string

	// Close releases any resources held by the cache.
	Close() error

	// Embedding cache.
	GetEmbedding(key, provider, model string) ([]float32, bool)
	PutEmbedding(key, provider, model string, vec []float32) error

	// Baseline.
	LoadBaseline() (map[string]struct{}, error)
	SaveBaseline(items map[string]string) error

	// Deep-tool result memoisation.
	GetDeepTool(key string) ([]byte, bool)
	PutDeepTool(key string, payload []byte) error

	// ContextPack memoisation. Key should be the Pack.CacheKey computed by
	// contextpack.Builder, which already hashes (chunk content, cfg). The
	// payload is opaque JSON.
	GetContextPack(key string) ([]byte, bool)
	PutContextPack(key string, payload []byte) error
}

// Compile-time check: *DB must satisfy Cache.
var _ Cache = (*DB)(nil)
