// WhoAmI — resolves a caller's own identity from THEIR OWN Openfort access
// token, as opposed to users.go/accounts.go which authenticate as the project
// (the OPENFORT_SECRET_KEY). This is what backend admin-gating falls back to
// when a caller's token isn't a JWT the process can decode itself — see
// everyflow.backend.asset-management-service/pkg/server/iam_admin_server.go.
package openfort

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Me mirrors Openfort's AuthUserResponse (GET /iam/v2/me).
type Me struct {
	ID    string  `json:"id"`
	Email *string `json:"email"`
}

// WhoAmI asks Openfort who a token belongs to, authenticating as the CALLER
// (their own token as the Bearer credential) rather than the project secret —
// it works whether or not OPENFORT_SECRET_KEY is configured.
func (c UsersConfig) WhoAmI(ctx context.Context, callerToken string) (*Me, error) {
	if callerToken == "" {
		return nil, errors.New("openfort: no caller token")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/iam/v2/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+callerToken)
	req.Header.Set("Accept", "application/json")
	if c.PublishableKey != "" {
		req.Header.Set("x-project-key", c.PublishableKey)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openfort whoami %d: %s", resp.StatusCode, string(raw))
	}
	var out Me
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("openfort whoami decode: %w", err)
	}
	return &out, nil
}
