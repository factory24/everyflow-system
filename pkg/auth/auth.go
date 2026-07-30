// Package auth is the shared Openfort-JWT verify layer for Everyflow's Connect
// services. Tokens are verified ONLY at the edge (asset-management-service);
// downstream services trust the propagated context (see iam-roles-and-views.md).
//
// Two modes, chosen by env:
//
//   - **Verified** (`OPENFORT_JWKS_URL` set): RS256 signature checked against the
//     Openfort JWKS, plus exp/nbf and optional iss/aud. See jwks.go.
//   - **Decode-only** (no JWKS URL): claims are decoded and expiry checked but the
//     signature is NOT verified. Local dev / demo only; logged loudly at startup.
//
// `AUTH_REQUIRE_TOKEN=true` additionally rejects requests carrying no Bearer token
// (the default is permissive so the dashboard's mock/demo mode keeps working).
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
)

// Claims is the subset of the token we act on.
type Claims struct {
	Subject string
	Scope   string
	Exp     int64
	Email   string
	Issuer  string
	// Verified is true only when the signature was checked against the JWKS.
	// Handlers that mutate state should refuse unverified claims in production.
	Verified bool
}

var (
	ErrMalformed = errors.New("malformed token")
	ErrExpired   = errors.New("token expired")
	ErrNoToken   = errors.New("missing bearer token")
)

// ValidateToken decodes a JWT's claims and checks expiry. Pure + unit-testable.
// Does NOT verify the signature — use VerifyOrDecode for the configured path.
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
	if v, ok := raw["email"].(string); ok {
		c.Email = v
	}
	if v, ok := raw["iss"].(string); ok {
		c.Issuer = v
	}
	if v, ok := raw["exp"].(float64); ok {
		c.Exp = int64(v)
		if time.Now().Unix() >= c.Exp {
			return nil, ErrExpired
		}
	}
	return c, nil
}

var (
	verifierOnce sync.Once
	verifier     *Verifier
)

// DefaultVerifier is the process-wide verifier, built from env on first use.
func DefaultVerifier() *Verifier {
	verifierOnce.Do(func() { verifier = VerifierFromEnv() })
	return verifier
}

// VerifyOrDecode verifies the token against the JWKS when configured, otherwise
// falls back to the decode-only path. Claims.Verified reports which happened.
func VerifyOrDecode(ctx context.Context, token string) (*Claims, error) {
	if v := DefaultVerifier(); v.Enabled() {
		return v.Verify(ctx, token)
	}
	return ValidateToken(token)
}

// BearerToken pulls the raw token out of an Authorization header. "" when absent.
func BearerToken(h http.Header) string {
	authz := h.Get("Authorization")
	if len(authz) > 7 && strings.EqualFold(authz[:7], "bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return ""
}

// RequireToken reports whether a missing token is a hard failure (AUTH_REQUIRE_TOKEN).
func RequireToken() bool {
	return strings.EqualFold(os.Getenv("AUTH_REQUIRE_TOKEN"), "true")
}

type ctxKey struct{}

// Interceptor validates a Bearer token when present and attaches claims to ctx.
// A MISSING token is allowed through unless AUTH_REQUIRE_TOKEN=true, so the
// dashboard's demo/mock mode keeps working before real login is wired.
func Interceptor() connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			token := BearerToken(req.Header())
			if token == "" {
				if RequireToken() {
					return nil, connect.NewError(connect.CodeUnauthenticated, ErrNoToken)
				}
				return next(ctx, req)
			}
			claims, err := VerifyOrDecode(ctx, token)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}
			return next(NewContext(ctx, claims), req)
		}
	})
}

// NewContext attaches claims to a context — used by the interceptor and by the
// edge's plain HTTP handlers, which sit outside the Connect pipeline.
func NewContext(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// FromContext returns the authenticated claims if a valid token was presented.
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}
