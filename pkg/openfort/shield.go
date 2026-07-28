// Package openfort — server-side Openfort Shield logic for embedded wallets, ported
// from the `npm create openfort` scaffold backend (everyflow/backend/src/app.ts,
// which used @openfort/openfort-node's createEncryptionSession). This is the Go
// equivalent so the real Everyflow services own it instead of the example app.
//
// The dashboard's NEXT_PUBLIC_CREATE_ENCRYPTED_SESSION_ENDPOINT points at the
// EncryptionSessionHandler (mounted on the public edge). On login the Openfort SDK
// POSTs there; the handler mints a Shield encryption session with the SERVER secret
// keys and returns its id, which the embedded wallet uses to recover its key share.
//
// Only SERVER secrets are used here (OPENFORT_SECRET_KEY, SHIELD_SECRET_KEY,
// SHIELD_ENCRYPTION_SHARE) — never shipped to the browser. See ENV-CONSOLIDATED.md.
package openfort

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// ShieldConfig holds the server-side Shield credentials + endpoint.
type ShieldConfig struct {
	SecretKey       string // OPENFORT_SECRET_KEY (sk_...) — Openfort project secret
	ShieldAPIKey    string // SHIELD_API_KEY — the Shield publishable key
	ShieldSecretKey string // SHIELD_SECRET_KEY — Shield secret
	EncryptionShare string // SHIELD_ENCRYPTION_SHARE
	ShieldBaseURL   string // default https://shield.openfort.io
	// AllowOrigin for CORS (the dashboard origin). "" ⇒ "*".
	AllowOrigin string
}

// ShieldConfigFromEnv builds the config from the standard env (Infisical-injected).
func ShieldConfigFromEnv() ShieldConfig {
	return ShieldConfig{
		SecretKey:       os.Getenv("OPENFORT_SECRET_KEY"),
		ShieldAPIKey:    os.Getenv("SHIELD_API_KEY"),
		ShieldSecretKey: os.Getenv("SHIELD_SECRET_KEY"),
		EncryptionShare: os.Getenv("SHIELD_ENCRYPTION_SHARE"),
		ShieldBaseURL:   envOr("SHIELD_BASE_URL", "https://shield.openfort.io"),
		AllowOrigin:     os.Getenv("OPENFORT_CORS_ORIGIN"),
	}
}

// Configured reports whether the required server secrets are present.
func (c ShieldConfig) Configured() bool {
	return c.ShieldAPIKey != "" && c.ShieldSecretKey != "" && c.EncryptionShare != ""
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

// CreateEncryptionSession registers a one-time Shield encryption session and returns
// its id. Mirrors @openfort/openfort-node's createEncryptionSession: POST to the
// Shield API with the api-key/api-secret headers + the encryption share.
func (c ShieldConfig) CreateEncryptionSession(ctx context.Context) (string, error) {
	if !c.Configured() {
		return "", errors.New("shield env not set (SHIELD_API_KEY/SHIELD_SECRET_KEY/SHIELD_ENCRYPTION_SHARE)")
	}
	body, _ := json.Marshal(map[string]string{"encryption_part": c.EncryptionShare})
	url := c.ShieldBaseURL + "/project/encryption-session"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.ShieldAPIKey)
	req.Header.Set("x-api-secret", c.ShieldSecretKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("shield %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("shield decode: %w", err)
	}
	if out.SessionID == "" {
		return "", errors.New("shield: empty session_id")
	}
	return out.SessionID, nil
}

// EncryptionSessionHandler returns the POST handler for
// /api/protected-create-encryption-session (matches the scaffold's route + response
// shape `{ "session": "<id>" }`). Handles CORS preflight for the browser call.
func EncryptionSessionHandler(cfg ShieldConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := cfg.AllowOrigin
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		session, err := cfg.CreateEncryptionSession(r.Context())
		if err != nil {
			log.Printf("openfort: create encryption session failed: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"session": session})
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
