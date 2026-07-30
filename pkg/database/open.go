package database

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Open connects with the driver implied by the DSN, so a single env var
// (`DATABASE_URL`) is the only difference between local dev and production:
//
//	postgres://user:pass@host:5432/everyflow_user?sslmode=require   → Postgres (prod)
//	file:everyflow_user.db?cache=shared                             → SQLite   (dev)
//
// SQLite uses the pure-Go glebarez driver, NOT gorm.io/driver/sqlite: the latter
// needs CGO, which the distroless images this ships in do not have.
//
// This is the entry point services should use. The Config/Connection interfaces
// elsewhere in this package are the older, heavier flow-system-shaped API.
func Open(dsn string, cfg *gorm.Config) (*gorm.DB, error) {
	if cfg == nil {
		cfg = &gorm.Config{}
	}
	if dsn == "" {
		return nil, fmt.Errorf("database: empty DSN")
	}

	if IsPostgres(dsn) {
		db, err := gorm.Open(postgres.Open(dsn), cfg)
		if err != nil {
			return nil, fmt.Errorf("database: postgres connect failed: %w", err)
		}
		return db, nil
	}

	// SQLite in a container is almost always a misconfiguration: the file lands in
	// the image's ephemeral filesystem, so every pod restart silently loses the
	// data — the same failure that logged FlowSupport users out on each restart.
	// Shout about it rather than let it look healthy.
	if inContainer() {
		log.Printf("database: ⚠ WARNING — using SQLite inside a container. " +
			"DATA WILL BE LOST ON RESTART. Set DATABASE_URL to a Postgres DSN for any " +
			"deployed environment.")
	}

	db, err := gorm.Open(sqlite.Open(sqliteDSN(dsn)), cfg)
	if err != nil {
		return nil, fmt.Errorf("database: sqlite open failed: %w", err)
	}
	return db, nil
}

// inContainer reports whether we're running inside a container, so a SQLite
// fallback can be flagged as the misconfiguration it almost certainly is.
// Kubernetes always injects KUBERNETES_SERVICE_HOST; /.dockerenv covers plain
// Docker.
func inContainer() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// sqliteDSN adds the pragmas SQLite needs to survive concurrent writers.
//
// Without them, two goroutines writing at once fail with SQLITE_BUSY — which
// surfaced as concurrent recharges erroring in the vault-credit test. Postgres
// handles this natively, so this only matters in dev, but dev is where the
// concurrency bugs get found:
//
//   - journal_mode(WAL): readers don't block the writer, and writes serialise
//     rather than colliding outright.
//   - busy_timeout(5000): a blocked writer waits up to 5s for the lock instead of
//     failing immediately.
//
// Existing pragmas in the caller's DSN are respected — this only fills in gaps.
func sqliteDSN(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	add := ""
	if !strings.Contains(dsn, "busy_timeout") {
		add += sep + "_pragma=busy_timeout(5000)"
		sep = "&"
	}
	if !strings.Contains(dsn, "journal_mode") {
		add += sep + "_pragma=journal_mode(WAL)"
	}
	return dsn + add
}

// IsPostgres reports whether the DSN targets Postgres. Both URL schemes and the
// libpq key=value form ("host=… user=…") are recognised.
func IsPostgres(dsn string) bool {
	l := strings.ToLower(strings.TrimSpace(dsn))
	return strings.HasPrefix(l, "postgres://") ||
		strings.HasPrefix(l, "postgresql://") ||
		(strings.Contains(l, "host=") && strings.Contains(l, "user="))
}

// Driver names the driver a DSN selects — for startup logs, so which database a
// pod actually connected to is never a guess.
func Driver(dsn string) string {
	if IsPostgres(dsn) {
		return "postgres"
	}
	return "sqlite"
}
