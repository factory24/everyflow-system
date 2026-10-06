// Users — server-side calls to Openfort's core management API (api.openfort.io),
// distinct from Shield (shield.go, a different sub-API for wallet key recovery).
//
// This backs the Everyflow admin dashboard's Users page, which shows the same
// account list as dashboard.openfort.io → Authentication → Users — not just the
// subset JIT-mirrored into user-service on a completed sign-in session.
package openfort

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"

	"github.com/factory24/everyflow-system/pkg/auth"
)

// UsersConfig holds the server-side credentials for Openfort's core REST API.
type UsersConfig struct {
	SecretKey      string // OPENFORT_SECRET_KEY (sk_...) — Bearer auth, scope users:read
	PublishableKey string // OPENFORT_PUBLISHABLE_KEY (pk_...) — same value as the dashboard's
	// VITE_OPENFORT_PUBLISHABLE_KEY. Required as the x-project-key header on
	// caller-token-authenticated calls (e.g. WhoAmI) so Openfort knows which
	// project the token belongs to; the secret key alone doesn't scope that.
	BaseURL     string // default https://api.openfort.io
	AllowOrigin string // dashboard origin for CORS ("" ⇒ "*") — shares OPENFORT_CORS_ORIGIN with Shield
}

// UsersConfigFromEnv builds the config from the standard env (Infisical-injected).
func UsersConfigFromEnv() UsersConfig {
	return UsersConfig{
		SecretKey:      envOr("OPENFORT_SECRET_KEY", ""),
		PublishableKey: envOr("OPENFORT_PUBLISHABLE_KEY", ""),
		BaseURL:        envOr("OPENFORT_API_BASE_URL", "https://api.openfort.io"),
		AllowOrigin:    envOr("OPENFORT_CORS_ORIGIN", ""),
	}
}

// Configured reports whether the required secret is present.
func (c UsersConfig) Configured() bool {
	return c.SecretKey != ""
}

// LinkedAccount mirrors Openfort's LinkedAccountResponseV2.
type LinkedAccount struct {
	Provider  string `json:"provider"`
	AccountID string `json:"accountId,omitempty"`
}

// User mirrors Openfort's AuthUserResponse (GET /v2/users data[] entries).
// CreatedAt is the epoch-millisecond timestamp Openfort returns as a JSON number.
type User struct {
	ID             string          `json:"id"`
	CreatedAt      float64         `json:"createdAt"`
	Name           string          `json:"name"`
	Email          *string         `json:"email"`
	EmailVerified  bool            `json:"emailVerified"`
	PhoneNumber    *string         `json:"phoneNumber"`
	IsAnonymous    bool            `json:"isAnonymous"`
	LinkedAccounts []LinkedAccount `json:"linkedAccounts"`
}

type userListResponse struct {
	Data  []User `json:"data"`
	Total int    `json:"total"`
}

// ListUsersParams are the pagination params forwarded to GET /v2/users.
type ListUsersParams struct {
	Limit int
	Skip  int
}

// ListUsers calls Openfort's core API for the project's full account list — the
// same one shown in dashboard.openfort.io → Authentication → Users. Auth is the
// project secret key as a Bearer token (scope users:read), per Openfort's
// published OpenAPI spec (securityScheme "sk").
func (c UsersConfig) ListUsers(ctx context.Context, p ListUsersParams) ([]User, int, error) {
	if !c.Configured() {
		return nil, 0, errors.New("openfort: OPENFORT_SECRET_KEY not set")
	}
	q := url.Values{}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Skip > 0 {
		q.Set("skip", strconv.Itoa(p.Skip))
	}
	reqURL := c.BaseURL + "/v2/users"
	if enc := q.Encode(); enc != "" {
		reqURL += "?" + enc
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.SecretKey)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("openfort users %d: %s", resp.StatusCode, string(raw))
	}
	var out userListResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, 0, fmt.Errorf("openfort users decode: %w", err)
	}
	return out.Data, out.Total, nil
}

// UsersHandler returns the GET handler for /api/admin/openfort-users.
//
// Admin-gated: this returns every project account's name/email/phone in one
// response, so a PRESENT bearer token must verify and its email must be on
// ADMIN_EMAILS, regardless of AUTH_REQUIRE_TOKEN. A MISSING token follows the
// same AUTH_REQUIRE_TOKEN posture as the rest of the edge (auth.Interceptor),
// so local/demo mode keeps working before real login is wired — matching the
// permissiveness that already applies to user-service's own ListUsers today.
func UsersHandler(cfg UsersConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := cfg.AllowOrigin
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if token := auth.BearerToken(r.Header); token != "" {
			claims, err := auth.VerifyOrDecode(r.Context(), token)
			if err != nil || !auth.IsAdminEmail(claims.Email) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		} else if auth.RequireToken() {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 100
		}
		skip, _ := strconv.Atoi(r.URL.Query().Get("skip"))

		users, total, err := cfg.ListUsers(r.Context(), ListUsersParams{Limit: limit, Skip: skip})
		if err != nil {
			log.Printf("openfort: list users failed: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "failed to fetch users from openfort"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"users": users, "total": total})
	}
}
