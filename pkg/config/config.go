package config

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4/middleware"
	echolog "github.com/labstack/gommon/log"
	"github.com/morkid/paginate"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type BaseConfig interface {
	LoadEnv(filenames ...string)
	IsProduction() bool
	IsDevelopment() bool
	IsTesting() bool
	GetDBConfig() *gorm.Config
	PaginateConfig() paginate.Config
	GetLogLevel() string
	GetEchoLogLevel() echolog.Lvl
	GetAppPort() string
	GetAppName() string
	GetSentryDSN() string
	GetAppEnv() string
	GetKeycloakBaseURL() string
	GetKeycloakRealm() string
	GetKeycloakClientID() string
	GetKeycloakClientSecret() string
	GetDBType() string
	GetDBName() string
	GetDBHost() string
	GetDBPort() string
	GetDBUser() string
	GetDBPass() string
	GetDBSSLMode() string
	GetSentryConfig() sentry.ClientOptions
	GetLogger() *slog.Logger
	GetSlogLevel() slog.Level
	GetEchoLoggerConfig() middleware.LoggerConfig
	GetServerAddr() string
}

type baseConfig struct{}

func NewBaseConfig() BaseConfig {
	return &baseConfig{}
}

func (c *baseConfig) LoadEnv(filenames ...string) {
	if err := godotenv.Load(filenames...); err != nil {
		log.Println("Warning: .env file not found or failed to load")
	} else {
		log.Println(".env loaded successfully")
	}
}

func (c *baseConfig) GetAppEnv() string {
	env := os.Getenv("APP.ENV")
	if env == "" {
		return "development"
	}
	return env
}

func (c *baseConfig) IsProduction() bool {
	return c.GetAppEnv() == "production"
}

func (c *baseConfig) IsDevelopment() bool {
	return c.GetAppEnv() == "development"
}

func (c *baseConfig) IsTesting() bool {
	return c.GetAppEnv() == "testing"
}

func (c *baseConfig) GetLogLevel() string {
	level := os.Getenv("LOG_LEVEL")
	if level == "" {
		level = "info"
	}
	return strings.ToLower(level)
}

func (c *baseConfig) GetEchoLogLevel() echolog.Lvl {
	level := os.Getenv("ECHO_LOG_LEVEL")
	if level == "" {
		level = c.GetLogLevel()
	}

	switch level {
	case "debug":
		return echolog.DEBUG
	case "info":
		return echolog.INFO
	case "warn":
		return echolog.WARN
	case "error":
		return echolog.ERROR
	case "off", "silent":
		return echolog.OFF
	default:
		return echolog.INFO
	}
}

func (c *baseConfig) GetSlogLevel() slog.Level {
	level := c.GetLogLevel()
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (c *baseConfig) GetDBConfig() *gorm.Config {
	logLevel := logger.Info
	envLogLevel := os.Getenv("DB_LOG_LEVEL")
	if envLogLevel == "" {
		envLogLevel = c.GetLogLevel()
	}

	switch envLogLevel {
	case "silent", "off":
		logLevel = logger.Silent
	case "error":
		logLevel = logger.Error
	case "warn":
		logLevel = logger.Warn
	case "info":
		logLevel = logger.Info
	case "debug":
		logLevel = logger.Info
	default:
		if c.IsProduction() && os.Getenv("DB_LOG_LEVEL") == "" && os.Getenv("LOG_LEVEL") == "" {
			logLevel = logger.Silent
		}
	}

	return &gorm.Config{
		SkipDefaultTransaction:                   false,
		NamingStrategy:                           nil,
		FullSaveAssociations:                     false,
		Logger:                                   logger.Default.LogMode(logLevel),
		NowFunc:                                  nil,
		DryRun:                                   false,
		PrepareStmt:                              false,
		DisableAutomaticPing:                     false,
		DisableForeignKeyConstraintWhenMigrating: false,
		IgnoreRelationshipsWhenMigrating:         false,
		DisableNestedTransaction:                 false,
		AllowGlobalUpdate:                        false,
		QueryFields:                              false,
		CreateBatchSize:                          0,
		TranslateError:                           true,
		ClauseBuilders:                           nil,
		ConnPool:                                 nil,
		Dialector:                                nil,
		Plugins:                                  nil,
	}
}

func (c *baseConfig) GetAppPort() string {
	port := os.Getenv("APP.PORT")
	if port == "" {
		port = os.Getenv("PORT")
	}
	if port == "" {
		port = "8080"
	}
	return port
}

func (c *baseConfig) GetAppName() string {
	return os.Getenv("APP.NAME")
}

func (c *baseConfig) GetSentryDSN() string {
	return os.Getenv("SENTRY.DSN")
}

func (c *baseConfig) GetKeycloakBaseURL() string {
	return os.Getenv("KC.BASE_URL")
}

func (c *baseConfig) GetKeycloakRealm() string {
	return os.Getenv("KC.REALM")
}

func (c *baseConfig) GetKeycloakClientID() string {
	return os.Getenv("KC.CLIENT_ID")
}

func (c *baseConfig) GetKeycloakClientSecret() string {
	return os.Getenv("KC.CLIENT_SECRET")
}

func (c *baseConfig) GetDBType() string {
	dbType := os.Getenv("DB.TYPE")
	if dbType == "" {
		dbType = "sqlite"
	}
	return dbType
}

func (c *baseConfig) GetDBName() string {
	return os.Getenv("DB.NAME")
}

func (c *baseConfig) GetDBHost() string {
	return os.Getenv("DB.HOST")
}

func (c *baseConfig) GetDBPort() string {
	return os.Getenv("DB.PORT")
}

func (c *baseConfig) GetDBUser() string {
	return os.Getenv("DB.USER")
}

func (c *baseConfig) GetDBPass() string {
	return os.Getenv("DB.PASS")
}

func (c *baseConfig) GetDBSSLMode() string {
	return os.Getenv("DB.SSLMODE")
}

func (c *baseConfig) GetSentryConfig() sentry.ClientOptions {
	sentrySyncTransport := sentry.NewHTTPSyncTransport()
	sentrySyncTransport.Timeout = time.Second * 3

	return sentry.ClientOptions{
		Dsn:              c.GetSentryDSN(),
		TracesSampleRate: 1.0,
		Debug:            c.IsDevelopment(),
		AttachStacktrace: true,
		ServerName:       c.GetAppName(),
		Environment:      c.GetAppEnv(),
		Transport:        sentrySyncTransport,
		EnableTracing:    true,
	}
}

func (c *baseConfig) GetLogger() *slog.Logger {
	var handler slog.Handler
	level := c.GetSlogLevel()
	if c.IsProduction() {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	return slog.New(handler)
}

func (c *baseConfig) GetEchoLoggerConfig() middleware.LoggerConfig {
	return middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339_nano}","id":"${id}","remote_ip":"${remote_ip}",` +
			`"host":"${host}","method":"${method}","uri":"${uri}","user_agent":"${user_agent}",` +
			`"status":${status},"error":"${error}","latency":${latency},"latency_human":"${latency_human}",` +
			`"bytes_in":${bytes_in},"bytes_out":${bytes_out}}` + "\n",
	}
}

func (c *baseConfig) GetServerAddr() string {
	return fmt.Sprintf(":%s", c.GetAppPort())
}

func (c *baseConfig) PaginateConfig() paginate.Config {
	return paginate.Config{
		DefaultSize:          10,
		FieldSelectorEnabled: true,
		ErrorEnabled:         true,
	}
}
