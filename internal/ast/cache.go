// Package ast — sqlite-backed parse cache.
//
// Tree-sitter parsing is fast, but on a large monorepo it still dominates the
// non-LLM cost of a scan. The cache key is sha256(content)+language so that
// renames don't invalidate entries and identical files in different paths
// share a single cached parse.
//
// Storage layout (single table):
//
//	ast_cache(key TEXT PK, lang TEXT, path TEXT, mtime INT, size INT,
//	          blob BLOB, stored_at INT)
//
// `blob` is the gob-encoded astBlob (source + extracted symbols/imports/calls).
// On a cache hit, the returned FileAST has root==nil — downstream consumers
// only read source / Imports / Symbols / Calls and never touch the
// tree-sitter root node, so this is safe.
package ast

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	// register the pure-Go SQLite driver under name "sqlite".
	_ "modernc.org/sqlite"
)

// CacheStats is a small counters bundle for diagnostics.
type CacheStats struct {
	Hits   int64
	Misses int64
	Stores int64
	Errors int64
}

// Cache is the AST cache handle. The zero value is unusable; use OpenCache.
// A nil *Cache is a valid no-op cache: every method returns sensible defaults.
type Cache struct {
	mu   sync.Mutex
	db   *sql.DB
	path string
	hits int64
	miss int64
	st   int64
	errs int64
}

// astBlob is what we serialize per entry. It mirrors FileAST minus the
// tree-sitter root pointer, which is not portable.
type astBlob struct {
	Path     string
	Language Language
	Imports  []Import
	Symbols  []Symbol
	Calls    []Call
	LOC      int
	Source   []byte
}

// OpenCache opens (or creates) the on-disk cache at `path`. If the parent
// directory cannot be created or the DB cannot be opened, it returns an
// error — callers are expected to log and fall back to nil (no-op cache).
func OpenCache(path string) (*Cache, error) {
	if path == "" {
		return nil, errors.New("ast cache: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("ast cache: mkdir: %w", err)
	}
	conn, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("ast cache: open: %w", err)
	}
	conn.SetMaxOpenConns(1) // sqlite tolerates a single writer best
	if _, err := conn.Exec(`CREATE TABLE IF NOT EXISTS ast_cache (
		key       TEXT PRIMARY KEY,
		lang      TEXT NOT NULL,
		path      TEXT NOT NULL,
		mtime     INTEGER NOT NULL,
		size      INTEGER NOT NULL,
		blob      BLOB NOT NULL,
		stored_at INTEGER NOT NULL
	)`); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ast cache: migrate: %w", err)
	}
	return &Cache{db: conn, path: path}, nil
}

// Close releases the underlying DB connection.
func (c *Cache) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Path returns the on-disk file path.
func (c *Cache) Path() string {
	if c == nil {
		return ""
	}
	return c.path
}

// Stats returns a snapshot of counters (safe for concurrent reads).
func (c *Cache) Stats() CacheStats {
	if c == nil {
		return CacheStats{}
	}
	return CacheStats{
		Hits:   atomic.LoadInt64(&c.hits),
		Misses: atomic.LoadInt64(&c.miss),
		Stores: atomic.LoadInt64(&c.st),
		Errors: atomic.LoadInt64(&c.errs),
	}
}

// Clear drops all cached entries.
func (c *Cache) Clear() error {
	if c == nil || c.db == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.db.Exec(`DELETE FROM ast_cache`)
	return err
}

// keyFor builds the lookup key from content + language. The path is *not*
// part of the key on purpose — moving a file should not invalidate its parse.
func keyFor(src []byte, lang Language) string {
	sum := sha256.Sum256(src)
	return hex.EncodeToString(sum[:]) + ":" + string(lang)
}

// Lookup returns the cached FileAST for the given file or (nil,false,nil) on
// a miss. A nil cache always misses (no error).
func (c *Cache) Lookup(absPath string, src []byte, lang Language) (*FileAST, bool, error) {
	if c == nil || c.db == nil {
		return nil, false, nil
	}
	key := keyFor(src, lang)
	c.mu.Lock()
	row := c.db.QueryRow(`SELECT blob FROM ast_cache WHERE key = ?`, key)
	var blob []byte
	err := row.Scan(&blob)
	c.mu.Unlock()
	if errors.Is(err, sql.ErrNoRows) {
		atomic.AddInt64(&c.miss, 1)
		return nil, false, nil
	}
	if err != nil {
		atomic.AddInt64(&c.errs, 1)
		return nil, false, err
	}
	a, derr := decodeBlob(blob)
	if derr != nil {
		atomic.AddInt64(&c.errs, 1)
		return nil, false, derr
	}
	// Overwrite path with the caller's absolute path — entries are content-
	// addressed and may legitimately be reused across files.
	a.Path = absPath
	atomic.AddInt64(&c.hits, 1)
	return a, true, nil
}

// Store writes the FileAST to the cache. Errors are surfaced but most callers
// can ignore them — a failed write only forfeits a future cache hit.
func (c *Cache) Store(a *FileAST) error {
	if c == nil || c.db == nil || a == nil {
		return nil
	}
	if len(a.source) == 0 {
		return nil
	}
	key := keyFor(a.source, a.Language)
	blob, err := encodeBlob(a)
	if err != nil {
		atomic.AddInt64(&c.errs, 1)
		return err
	}
	var (
		mtime int64
		size  int64
	)
	if st, err := os.Stat(a.Path); err == nil {
		mtime = st.ModTime().Unix()
		size = st.Size()
	}
	c.mu.Lock()
	_, err = c.db.Exec(
		`INSERT OR REPLACE INTO ast_cache(key, lang, path, mtime, size, blob, stored_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		key, string(a.Language), a.Path, mtime, size, blob, time.Now().Unix(),
	)
	c.mu.Unlock()
	if err != nil {
		atomic.AddInt64(&c.errs, 1)
		return err
	}
	atomic.AddInt64(&c.st, 1)
	return nil
}

func encodeBlob(a *FileAST) ([]byte, error) {
	b := astBlob{
		Path:     a.Path,
		Language: a.Language,
		Imports:  a.Imports,
		Symbols:  a.Symbols,
		Calls:    a.Calls,
		LOC:      a.LOC,
		Source:   a.source,
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeBlob(raw []byte) (*FileAST, error) {
	var b astBlob
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&b); err != nil {
		return nil, err
	}
	return &FileAST{
		Path:     b.Path,
		Language: b.Language,
		Imports:  b.Imports,
		Symbols:  b.Symbols,
		Calls:    b.Calls,
		LOC:      b.LOC,
		source:   b.Source,
		// root is intentionally left nil — see package doc.
	}, nil
}
