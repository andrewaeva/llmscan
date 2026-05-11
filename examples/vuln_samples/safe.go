// Intentionally clean sample. The FP filter / verifier should NOT raise findings here.
package vuln

import (
	"database/sql"
	"fmt"
)

func GetUser(db *sql.DB, id int) (string, error) {
	row := db.QueryRow("SELECT name FROM users WHERE id = ?", id)
	var name string
	if err := row.Scan(&name); err != nil {
		return "", fmt.Errorf("scan: %w", err)
	}
	return name, nil
}
