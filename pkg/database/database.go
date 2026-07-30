package database

import (
	"fmt"
	"log"
	"math"
	"os"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/plugin/opentelemetry/tracing"
)

type Config interface {
	GetDBConfig() *gorm.Config
	GetDBType() string
	GetDBName() string
	GetDBHost() string
	GetDBPort() string
	GetDBUser() string
	GetDBPass() string
	GetDBSSLMode() string
}

type Connection interface {
	GetEngine() *gorm.DB
	Connect()
	MigrateDB()
}

type gormDB struct {
	engine     *gorm.DB
	models     []interface{}
	cfg        Config
	gormConfig *gorm.Config
}

func (db *gormDB) GetEngine() *gorm.DB {
	return db.engine
}

func NewGormDatabase(config Config, models []interface{}, gormConfigs ...*gorm.Config) Connection {
	var gormConfig *gorm.Config
	if len(gormConfigs) > 0 {
		gormConfig = gormConfigs[0]
	}

	return &gormDB{
		cfg:        config,
		models:     models,
		gormConfig: gormConfig,
	}
}

func (db *gormDB) getDialect() (gorm.Dialector, string, error) {
	var d gorm.Dialector

	dbType := db.cfg.GetDBType()

	switch dbType {
	case "sqlite":
		// Name only — no path required, matching the platform convention. The
		// pragmas matter: without WAL + busy_timeout, two concurrent writers fail
		// with SQLITE_BUSY, and a read-then-write transaction deadlocks with
		// SQLITE_BUSY_SNAPSHOT (517), which busy_timeout will NOT retry.
		dbName := fmt.Sprintf("%s.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)",
			db.cfg.GetDBName())
		d = sqlite.Open(dbName)

		// SQLite in a container is nearly always a misconfiguration: the file lives
		// in the pod's ephemeral filesystem, so every restart silently loses the
		// data. Say so loudly rather than let it look healthy.
		if inContainer() {
			log.Printf("database: ⚠ WARNING — SQLite inside a container. DATA WILL BE " +
				"LOST ON RESTART. Set DB.TYPE=postgres (DB_TYPE) for any deployed environment.")
		}
	case "postgres":
		dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s",
			db.cfg.GetDBHost(),
			db.cfg.GetDBUser(),
			db.cfg.GetDBPass(),
			db.cfg.GetDBName(),
			db.cfg.GetDBPort(),
		)

		if db.cfg.GetDBSSLMode() != "" {
			dsn = fmt.Sprintf("%s sslmode=%s", dsn, db.cfg.GetDBSSLMode())
		}
		d = postgres.Open(dsn)
	default:
		return nil, "", fmt.Errorf("unsupported database type: %s", dbType)
	}

	return d, dbType, nil
}

func (db *gormDB) Connect() {
	var counts int64
	var backOff = 1 * time.Second
	var connection *gorm.DB

	dialect, dbType, err := db.getDialect()
	if err != nil {
		log.Fatalf("failed to get db dialect: %v", err)
	}

	sslMode := db.cfg.GetDBSSLMode()
	if sslMode == "" {
		sslMode = "default (prefer)"
	}

	log.Printf("Connecting to %s database at %s:%s (name: %s, user: %s, sslmode: %s)...",
		dbType, db.cfg.GetDBHost(), db.cfg.GetDBPort(), db.cfg.GetDBName(), db.cfg.GetDBUser(), sslMode)

	for {
		gormConfig := db.gormConfig
		if gormConfig == nil {
			gormConfig = db.cfg.GetDBConfig()
		}

		c, err := gorm.Open(dialect, gormConfig)
		if err != nil {
			log.Printf("%s DB not yet ready to connect! Attempt %d. Error: %v", dbType, counts+1, err)
			counts++
		} else {
			connection = c
			break
		}

		if counts > 5 {
			log.Fatalf("failed to connect to %s database after 5 attempts", dbType)
		}

		backOff = time.Duration(math.Pow(float64(counts), 2)) * time.Second
		log.Printf("Backing off for %v...", backOff)
		time.Sleep(backOff)
	}

	log.Printf("%s database connected successfully\n", dbType)

	// Without this, every service was completely invisible in DB call
	// tracing (SigNoz/Jaeger's "DB Call Metrics" tab) regardless of how much
	// other tracing worked — no db.system/db.statement/duration spans were
	// ever emitted for any query, in any service, before this. Uses
	// whatever TracerProvider athari-thirdparty/tracing.Connect() already
	// registered globally, same as the HTTP client and Pulsar wiring.
	if err := connection.Use(tracing.NewPlugin()); err != nil {
		log.Printf("WARNING: failed to register GORM OTel tracing plugin: %v", err)
	}

	db.engine = connection
	db.MigrateDB()
}

func (db *gormDB) MigrateDB() {
	if len(db.models) > 0 {
		if err := db.engine.AutoMigrate(db.models...); err != nil {
			log.Fatalf("migration failed: %v", err)
		}
		log.Println("tables migrated successfully!")
	}
}

// inContainer reports whether we're running inside a container, so a SQLite
// fallback can be flagged as the misconfiguration it almost certainly is.
// Kubernetes always injects KUBERNETES_SERVICE_HOST; /.dockerenv covers Docker.
func inContainer() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	_, err := os.Stat("/.dockerenv")
	return err == nil
}
