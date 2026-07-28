// Package auth is the shared Openfort-JWT verify interceptor for Everyflow's
// Connect services (was per-service in asset-management). Verified ONLY at the edge;
// downstream services trust the propagated context (see iam-roles-and-views.md).
//
// ⚠ STUB: decodes claims + checks exp only — does NOT verify the signature. Real
// verification (fetch+cache OPENFORT JWKS, verify RS256, check iss/aud, require
// scope ∋ user:basic) lands next, configured via OPENFORT_JWKS_URL / OPENFORT_ISSUER
// / OPENFORT_AUDIENCE. Auth pivoted Dynamic → Openfort (see PIVOT-OPENFORT-PLAN.md).
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"
)

type Claims struct {
	Subject string
	Scope   string
	Exp     int64
}

var (
	ErrMalformed = errors.New("malformed token")
	ErrExpired   = errors.New("token expired")
)

// ValidateToken decodes a JWT's claims and checks expiry. Pure + unit-testable.
// Does NOT verify the signature (stub — see package doc).
func ValidateToken(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, ErrMalformed
	}
	c := &Claims{}
	if v, ok := raw["sub"].(string); ok {
		c.Subject = v
	}
	if v, ok := raw["scope"].(string); ok {
		c.Scope = v
	}
	if v, ok := raw["exp"].(float64); ok {
		c.Exp = int64(v)
		if time.Now().Unix() >= c.Exp {
			return nil, ErrExpired
		}
	}
	return c, nil
}

type ctxKey struct{}

// Interceptor validates a Bearer token when present and attaches claims to ctx.
// Demo mode: a MISSING token is allowed through (so the frontend works before real
// login is wired). Production requires the token + scope ∋ user:basic.
func Interceptor() connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			authz := req.Header().Get("Authorization")
			if strings.HasPrefix(authz, "Bearer ") {
				claims, err := ValidateToken(strings.TrimPrefix(authz, "Bearer "))
				if err != nil {
					return nil, connect.NewError(connect.CodeUnauthenticated, err)
				}
				ctx = context.WithValue(ctx, ctxKey{}, claims)
			}
			return next(ctx, req)
		}
	})
}

// FromContext returns the authenticated claims if a valid token was presented.
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}
