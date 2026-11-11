// Opaque Openfort access tokens.
//
// The access token the browser gets from Openfort's SDK (getAccessToken()) is NOT a JWT: it is an
// opaque session credential (~80 random characters, no dots). Nothing can be verified from the
// token itself — the only authority is Openfort, which will say who it belongs to if asked with
// that token (GET /iam/v2/me). Without this file every service answers an opaque token with
// "malformed token", so a signed-in user's calls were rejected before any handler or caller guard
// ran, and "verified identity" could never be true for a real browser session.
//
// VerifyOrDecode routes any token that is not JWT-shaped (exactly three dot-separated segments)
// here. JWT-shaped tokens — including service tokens and any forged unsigned one — keep going
// through the existing JWKS / decode path untouched, so this never loosens that path.
//
// Trust model: the identity comes from Openfort's own response to the caller's own token, over
// TLS, so Claims.Verified=true is honest — a forged token simply isn't known to Openfort and is
// rejected. Results are cached briefly so a page that makes many calls costs one lookup.
//
// Config (env, all optional — when no project can be identified the feature stays OFF and
// non-JWT tokens are rejected exactly as before):
//
//	OPENFORT_PUBLISHABLE_KEY  the project's pk_… key, sent as x-project-key. When blank it is
//	                          derived from OPENFORT_JWKS_URL (…/iam/v1/<pk>/jwks.json).
//	OPENFORT_API_BASE_URL     default https://api.openfort.io
//	OPENFORT_OPAQUE_TOKENS    "off" disables this path (kill switch)
//
// Standard library only, like the rest of this package (vendored service builds stay offline).
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	opaquePositiveTTL = 60 * time.Second // a verified identity is reused this long
	opaqueNegativeTTL = 5 * time.Second  // a rejected token is not re-asked immediately
	opaqueMaxEntries  = 5000             // bounds memory; cleared wholesale when exceeded
	opaqueLookupLimit = 5 * time.Second  // per-lookup timeout against Openfort
)

var (
	// ErrOpaqueRejected means Openfort did not recognise the token (unknown, expired, revoked).
	ErrOpaqueRejected = errors.New("token not recognised by openfort")
	// ErrOpaqueUnavailable means Openfort could not be asked right now (network / 5xx). Never cached.
	ErrOpaqueUnavailable = errors.New("could not verify token with openfort")
)

var jwksProjectKey = regexp.MustCompile(`/iam/v1/([^/]+)/jwks\.json`)

type opaqueEntry struct {
	claims *Claims
	err    error
	until  time.Time
}

var (
	opaqueMu    sync.Mutex
	opaqueCache = map[[32]byte]opaqueEntry{}
	opaqueHTTP  = &http.Client{Timeout: opaqueLookupLimit}
	opaqueOnce  sync.Once
)

// looksLikeJWT reports whether token has the three-segment JWT shape. It says nothing about
// validity — only which verification path the token belongs to.
func looksLikeJWT(token string) bool { return strings.Count(token, ".") == 2 }

// opaqueProjectKey returns the project's publishable key from env, or "" when none can be found.
func opaqueProjectKey() string {
	if k := strings.TrimSpace(os.Getenv("OPENFORT_PUBLISHABLE_KEY")); k != "" {
		return k
	}
	if m := jwksProjectKey.FindStringSubmatch(os.Getenv("OPENFORT_JWKS_URL")); m != nil {
		return m[1]
	}
	return ""
}

// OpaqueEnabled reports whether non-JWT tokens will be resolved through Openfort.
func OpaqueEnabled() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("OPENFORT_OPAQUE_TOKENS")), "off") {
		return false
	}
	return opaqueProjectKey() != ""
}

// resolveOpaque turns an opaque Openfort access token into verified claims.
func resolveOpaque(ctx context.Context, token string) (*Claims, error) {
	key := sha256.Sum256([]byte(token))

	opaqueMu.Lock()
	if e, ok := opaqueCache[key]; ok && time.Now().Before(e.until) {
		opaqueMu.Unlock()
		return e.claims, e.err
	}
	opaqueMu.Unlock()

	opaqueOnce.Do(func() {
		log.Printf("auth: opaque Openfort tokens are resolved via %s/iam/v2/me (cached %s)", opaqueBaseURL(), opaquePositiveTTL)
	})

	claims, err := fetchOpaque(ctx, token)

	// Transient failures are never cached: a blip must not lock a user out for a minute.
	if errors.Is(err, ErrOpaqueUnavailable) {
		return nil, err
	}
	ttl := opaquePositiveTTL
	if err != nil {
		ttl = opaqueNegativeTTL
	}
	opaqueMu.Lock()
	if len(opaqueCache) >= opaqueMaxEntries {
		now := time.Now()
		for k, e := range opaqueCache {
			if now.After(e.until) {
				delete(opaqueCache, k)
			}
		}
		if len(opaqueCache) >= opaqueMaxEntries {
			opaqueCache = map[[32]byte]opaqueEntry{}
		}
	}
	opaqueCache[key] = opaqueEntry{claims: claims, err: err, until: time.Now().Add(ttl)}
	opaqueMu.Unlock()
	return claims, err
}

func opaqueBaseURL() string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("OPENFORT_API_BASE_URL")), "/"); v != "" {
		return v
	}
	return "https://api.openfort.io"
}

func fetchOpaque(ctx context.Context, token string) (*Claims, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opaqueBaseURL()+"/iam/v2/me", nil)
	if err != nil {
		return nil, ErrOpaqueRejected // e.g. a token with characters not allowed in a header
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if pk := opaqueProjectKey(); pk != "" {
		req.Header.Set("x-project-key", pk)
	}

	resp, err := opaqueHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOpaqueUnavailable, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
		return nil, ErrOpaqueRejected
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, fmt.Errorf("%w: openfort returned %d", ErrOpaqueUnavailable, resp.StatusCode)
	}

	var me struct {
		ID    string  `json:"id"`
		Email *string `json:"email"`
	}
	if err := json.Unmarshal(raw, &me); err != nil || me.ID == "" {
		return nil, ErrOpaqueRejected
	}
	claims := &Claims{
		Subject:  me.ID,
		Issuer:   "openfort",
		Exp:      time.Now().Add(opaquePositiveTTL).Unix(),
		Verified: true, // Openfort itself authenticated this token
	}
	if me.Email != nil {
		claims.Email = *me.Email
	}
	return claims, nil
}

// resetOpaqueCache is for tests.
func resetOpaqueCache() {
	opaqueMu.Lock()
	opaqueCache = map[[32]byte]opaqueEntry{}
	opaqueMu.Unlock()
}
