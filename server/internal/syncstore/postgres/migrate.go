package postgres

import (
	"context"
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

// RunMigrations applies embedded goose migrations to db.
func RunMigrations(ctx context.Context, db *sql.DB) error {
	var initErr error
	migrateOnce.Do(func() {
		goose.SetLogger(log.New(io.Discard, "", 0))
		goose.SetBaseFS(migrations)
		initErr = goose.SetDialect("postgres")
	})
	if initErr != nil {
		return fmt.Errorf("configuring migrations: %w", initErr)
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}
