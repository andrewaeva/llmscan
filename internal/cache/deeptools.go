package cache

import "time"

// GetDeepTool returns a cached tool result for the given key.
// Key should be a stable hash of (tool, args, root, file mtime).
func (d *DB) GetDeepTool(key string) ([]byte, bool) {
	if d == nil {
		return nil, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(`SELECT payload FROM deep_tool_cache WHERE key=?`, key)
	var blob []byte
	if err := row.Scan(&blob); err != nil {
		return nil, false
	}
	return blob, true
}

// PutDeepTool stores a tool result under the given key.
func (d *DB) PutDeepTool(key string, payload []byte) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Exec(
		`INSERT OR REPLACE INTO deep_tool_cache(key, payload, created_at) VALUES(?,?,?)`,
		key, payload, time.Now().Unix(),
	)
	return err
}
