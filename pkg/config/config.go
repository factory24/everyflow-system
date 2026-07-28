// Package config — shared env helpers for the Everyflow services (the lean,
// Connect-native analogue of flow-system's config layer). Keeps the everyflow
// services standalone: no Echo/GORM/Keycloak baggage, just env access + a minimal
// .env loader for local dev. Secrets come from Infisical (see pkg/infisical).
package config

import (
	"bufio"
	"os"
	"strings"
)

// Env returns the value of key, or def when unset/empty.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// MustEnv returns the value of key or panics — use for values with no safe default.
func MustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("required env var not set: " + key)
	}
	return v
}

// AppEnv is the deployment environment ("dev" | "prod" | ...), from APP_ENV.
func AppEnv() string { return Env("APP_ENV", "dev") }

// IsProduction reports whether APP_ENV is prod.
func IsProduction() bool { return AppEnv() == "prod" }

// LoadDotEnv loads KEY=VALUE lines from a .env file into the process env (only for
// keys not already set), for local dev. Missing file is a no-op. Dependency-free.
func LoadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
}
