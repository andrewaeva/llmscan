// Package cache provides a small sqlite-backed key/value cache used for
// embeddings, chunk indices and baseline storage. Pure-Go (modernc.org/sqlite),
// no CGO needed.
//
// Three logical stores live in the same DB file:
//   - embeddings(key TEXT PRIMARY KEY, provider TEXT, model TEXT, dim INT, vec BLOB)
//   - rag_chunks(key TEXT PRIMARY KEY, file TEXT, payload BLOB)
//   - baseline(fingerprint TEXT PRIMARY KEY, finding_json TEXT, created_at INT)
//
// All accessors are safe for concurrent use; sqlite serializes writes.
package cache

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	// register the pure-Go SQLite driver under name "sqlite".
	_ "modernc.org/sqlite"
)

// DB is a thin wrapper.
type DB struct {
	mu   sync.Mutex
	conn *sql.DB
	path string
}

// Open opens (or creates) the cache db.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("cache: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("cache: mkdir: %w", err)
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("cache: open: %w", err)
	}
	conn.SetMaxOpenConns(1) // sqlite + writer concurrency
	d := &DB{conn: conn, path: path}
	if err := d.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	return d, nil
}

// Path returns the underlying file path.
func (d *DB) Path() string { return d.path }

// Close releases the underlying connection.
func (d *DB) Close() error {
	if d == nil || d.conn == nil {
		return nil
	}
	return d.conn.Close()
}

func (d *DB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS embeddings (
			key      TEXT PRIMARY KEY,
			provider TEXT NOT NULL,
			model    TEXT NOT NULL,
			dim      INTEGER NOT NULL,
			vec      BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS rag_chunks (
			key      TEXT PRIMARY KEY,
			file     TEXT NOT NULL,
			payload  BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS baseline (
			fingerprint TEXT PRIMARY KEY,
			finding_json TEXT NOT NULL,
			created_at   INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS deep_tool_cache (
			key         TEXT PRIMARY KEY,
			payload     BLOB NOT NULL,
			created_at  INTEGER NOT NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := d.conn.Exec(s); err != nil {
			return fmt.Errorf("cache: migrate: %w", err)
		}
	}
	return nil
}

// ---- Embedding cache ----

// GetEmbedding returns a vector if cached for (key, provider, model).
func (d *DB) GetEmbedding(key, provider, model string) ([]float32, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT vec FROM embeddings WHERE key=? AND provider=? AND model=?`,
		key, provider, model,
	)
	var blob []byte
	if err := row.Scan(&blob); err != nil {
		return nil, false
	}
	return decodeFloats(blob), true
}

// PutEmbedding stores a vector.
func (d *DB) PutEmbedding(key, provider, model string, vec []float32) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT OR REPLACE INTO embeddings(key,provider,model,dim,vec) VALUES(?,?,?,?,?)`,
		key, provider, model, len(vec), encodeFloats(vec),
	)
	return err
}

// ---- Baseline ----

// LoadBaseline returns the set of known fingerprints.
func (d *DB) LoadBaseline() (map[string]struct{}, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT fingerprint FROM baseline`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out[fp] = struct{}{}
	}
	return out, nil
}

// SaveBaseline replaces the baseline with the supplied fingerprints+payloads.
func (d *DB) SaveBaseline(items map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM baseline`); err != nil {
		_ = tx.Rollback()
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO baseline(fingerprint, finding_json, created_at) VALUES(?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	for fp, payload := range items {
		if _, err := stmt.Exec(fp, payload, now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ---- helpers ----

func encodeFloats(v []float32) []byte {
	buf := make([]byte, 4*len(v))
	for i, f := range v {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
	}
	return buf
}

func decodeFloats(b []byte) []float32 {
	n := len(b) / 4
	out := make([]float32, n)
	for i := 0; i < n; i++ {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[i*4:]))
	}
	return out
}
