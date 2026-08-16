package sqlite

import (
	"database/sql"
	"embed"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

var migrateOnce sync.Once

func runMigrations(db *sql.DB) error {
	var initErr error
	migrateOnce.Do(func() {
		goose.SetLogger(log.New(io.Discard, "", 0))
		goose.SetBaseFS(migrations)
		initErr = goose.SetDialect("sqlite3")
	})
	if initErr != nil {
		return fmt.Errorf("configuring migrations: %w", initErr)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}
