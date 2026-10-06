// Accounts — server-side calls to Openfort's core management API
// (api.openfort.io), same sub-API as users.go, for a player's on-chain
// accounts (embedded wallets).
//
// Two different ID namespaces are in play here, and mixing them up silently
// returns zero results rather than an error: the JWT subject / AuthUserResponse.id
// is a "usr_..." auth identity, while GET /v2/accounts filters by "pla_..." player
// (a.k.a. wallet) id. GetUserWallet bridges the two via Openfort's dedicated
// GET /v2/users/{id}/wallet endpoint, which is the ONLY thing that takes a usr_ id
// directly — resolve that first, then pass its id into ListAccounts.
package openfort

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Wallet mirrors Openfort's BaseEntityResponseEntityTypeWALLET (GET
// /v2/users/{id}/wallet) — its ID is the pla_... player/wallet id ListAccounts
// expects, NOT an account address.
type Wallet struct {
	ID        string  `json:"id"`
	CreatedAt float64 `json:"createdAt"`
}

// GetUserWallet resolves an auth user (usr_...) to their player/wallet id
// (pla_...). A user with no wallet provisioned yet (embedded wallet creation can
// lag sign-up) returns a non-2xx status, surfaced as an error — callers should
// treat that as "not yet available," not fatal.
func (c UsersConfig) GetUserWallet(ctx context.Context, userID string) (*Wallet, error) {
	if !c.Configured() {
		return nil, errors.New("openfort: OPENFORT_SECRET_KEY not set")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v2/users/"+url.PathEscape(userID)+"/wallet", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.SecretKey)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openfort user wallet %d: %s", resp.StatusCode, string(raw))
	}
	var out Wallet
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("openfort user wallet decode: %w", err)
	}
	return &out, nil
}

// Account mirrors Openfort's AccountV2Response (GET /v2/accounts data[] entries).
type Account struct {
	ID        string  `json:"id"`
	Address   string  `json:"address"`
	Wallet    string  `json:"wallet"`
	ChainType string  `json:"chainType"`
	ChainID   *int    `json:"chainId,omitempty"`
	CreatedAt float64 `json:"createdAt"`
}

type accountListResponse struct {
	Data  []Account `json:"data"`
	Total int       `json:"total"`
}

// ListAccountsParams are the filter/pagination params forwarded to GET /v2/accounts.
type ListAccountsParams struct {
	User  string // Openfort player id (starts with pla_) — filters to one user's accounts
	Limit int
}

// ListAccounts calls Openfort's core API for a player's blockchain accounts —
// same secret-key Bearer auth as ListUsers.
func (c UsersConfig) ListAccounts(ctx context.Context, p ListAccountsParams) ([]Account, int, error) {
	if !c.Configured() {
		return nil, 0, errors.New("openfort: OPENFORT_SECRET_KEY not set")
	}
	q := url.Values{}
	if p.User != "" {
		q.Set("user", p.User)
	}
	limit := p.Limit
	if limit <= 0 {
		limit = 100
	}
	q.Set("limit", strconv.Itoa(limit))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v2/accounts?"+q.Encode(), nil)
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
		return nil, 0, fmt.Errorf("openfort accounts %d: %s", resp.StatusCode, string(raw))
	}
	var out accountListResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, 0, fmt.Errorf("openfort accounts decode: %w", err)
	}
	return out.Data, out.Total, nil
}
