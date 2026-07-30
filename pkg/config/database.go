package config

import (
	"log"
	"os"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DBConfig implements database.Config using the SAME env contract as the rest of
// the Flow platform, so a service is configured by discrete fields rather than a
// hand-assembled DSN:
//
//	DB.TYPE      sqlite | postgres      (default sqlite)
//	DB.NAME      database name          — for sqlite this is ALL you need; the
//	                                      driver writes <name>.db, no path required
//	DB.HOST      postgres only
//	DB.PORT      postgres only
//	DB.USER      postgres only
//	DB.PASS      postgres only
//	DB.SSLMODE   postgres only (blank ⇒ driver default)
//
// Every key is also accepted with an UNDERSCORE (`DB_TYPE`, `DB_NAME`, …), and
// that spelling is the one to use in Kubernetes: a ConfigMap mounted with
// `envFrom` has each key validated as a C_IDENTIFIER, and kubelet **silently
// skips** any key containing a dot — recording only an `InvalidVariableNames`
// event. A pod configured with `DB.TYPE` would therefore fall back to sqlite and
// look perfectly healthy while writing to an ephemeral file.
type DBConfig struct{}

// NewDBConfig returns the env-backed database config.
func NewDBConfig() *DBConfig { return &DBConfig{} }

// dbEnv reads a DB setting, accepting both `DB.NAME` and `DB_NAME` spellings.
func dbEnv(name string) string {
	if v := os.Getenv("DB." + name); v != "" {
		return v
	}
	return os.Getenv("DB_" + name)
}

// GetDBType is the driver: sqlite (default) or postgres.
func (c *DBConfig) GetDBType() string {
	if t := dbEnv("TYPE"); t != "" {
		return t
	}
	return "sqlite"
}

// GetDBName is the database name. For sqlite it is the whole configuration —
// the driver derives the filename from it.
func (c *DBConfig) GetDBName() string { return dbEnv("NAME") }

func (c *DBConfig) GetDBHost() string    { return dbEnv("HOST") }
func (c *DBConfig) GetDBPort() string    { return dbEnv("PORT") }
func (c *DBConfig) GetDBUser() string    { return dbEnv("USER") }
func (c *DBConfig) GetDBPass() string    { return dbEnv("PASS") }
func (c *DBConfig) GetDBSSLMode() string { return dbEnv("SSLMODE") }

// GetDBConfig is the GORM config. Query logging is quiet by default and raised
// with DB_LOG_LEVEL=info|warn|error|silent — GORM's default logs every statement,
// which floods production logs and can echo values into them.
func (c *DBConfig) GetDBConfig() *gorm.Config {
	return &gorm.Config{Logger: logger.Default.LogMode(logLevel())}
}

func logLevel() logger.LogLevel {
	switch os.Getenv("DB_LOG_LEVEL") {
	case "info":
		return logger.Info
	case "warn":
		return logger.Warn
	case "silent":
		return logger.Silent
	default:
		return logger.Error
	}
}

// Describe is a one-line, SECRET-FREE summary for the startup log. It never
// includes the password — a DSN logged in full is a credential leak into cluster
// log aggregation.
func (c *DBConfig) Describe() string {
	if c.GetDBType() == "sqlite" {
		return "sqlite name=" + c.GetDBName()
	}
	return "postgres host=" + c.GetDBHost() + ":" + c.GetDBPort() +
		" db=" + c.GetDBName() + " user=" + c.GetDBUser() + " sslmode=" + c.GetDBSSLMode()
}

// Validate fails fast on a misconfiguration that would otherwise surface much
// later as a confusing connection error.
func (c *DBConfig) Validate() {
	if c.GetDBName() == "" {
		log.Fatal("config: DB.NAME / DB_NAME is required")
	}
	if c.GetDBType() == "postgres" {
		missing := []string{}
		if c.GetDBHost() == "" {
			missing = append(missing, "DB_HOST")
		}
		if c.GetDBUser() == "" {
			missing = append(missing, "DB_USER")
		}
		if len(missing) > 0 {
			log.Fatalf("config: DB.TYPE=postgres but %v not set", missing)
		}
	}
}
