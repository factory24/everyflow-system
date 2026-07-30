// JWKS-backed RS256 verification for Openfort access tokens. This replaces the
// claim-decode stub in auth.go with real signature verification.
//
// Config (env, Infisical-injected — see flow-next-phase/ENV-CONSOLIDATED.md):
//
//	OPENFORT_JWKS_URL   e.g. https://api.openfort.io/iam/v1/<publishable>/jwks.json
//	OPENFORT_ISSUER     expected `iss` (optional — skipped when blank)
//	OPENFORT_AUDIENCE   expected `aud` (optional — skipped when blank)
//	OPENFORT_JWKS_TTL   key-cache TTL, Go duration (default 10m)
//
// When OPENFORT_JWKS_URL is blank the verifier is DISABLED and callers fall back
// to the unsigned decode path (local dev / demo). That fallback is logged loudly
// at startup so a prod deployment missing the URL is obvious.
//
// Implemented with the standard library only (crypto/rsa + crypto/sha256) — no new
// module dependency, so the vendored service builds keep working offline.
package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ErrBadSignature  = errors.New("token signature invalid")
	ErrUnknownKey    = errors.New("token kid not found in JWKS")
	ErrBadAlgorithm  = errors.New("unsupported token algorithm")
	ErrBadIssuer     = errors.New("token issuer mismatch")
	ErrBadAudience   = errors.New("token audience mismatch")
	ErrNotYetValid   = errors.New("token not yet valid")
	ErrJWKSUnhealthy = errors.New("could not fetch JWKS")
)

// clockSkew tolerates small clock drift between the IdP and this service.
const clockSkew = 60 * time.Second

// Verifier verifies Openfort JWTs against the project's JWKS, caching keys by kid.
type Verifier struct {
	jwksURL  string
	issuer   string
	audience string
	ttl      time.Duration
	client   *http.Client

	mu sync.RWMutex
	// keys holds *rsa.PublicKey or *ecdsa.PublicKey by kid. Openfort signs with
	// EC P-256 (ES256); other IdPs use RSA — both must work.
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

// VerifierFromEnv builds the verifier from the standard env. Always returns a
// non-nil Verifier; check Enabled() to see whether real verification is on.
func VerifierFromEnv() *Verifier {
	ttl := 10 * time.Minute
	if raw := os.Getenv("OPENFORT_JWKS_TTL"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			ttl = d
		}
	}
	return &Verifier{
		jwksURL:  os.Getenv("OPENFORT_JWKS_URL"),
		issuer:   os.Getenv("OPENFORT_ISSUER"),
		audience: os.Getenv("OPENFORT_AUDIENCE"),
		ttl:      ttl,
		client:   &http.Client{Timeout: 10 * time.Second},
		keys:     map[string]crypto.PublicKey{},
	}
}

// Enabled reports whether a JWKS URL is configured (i.e. signatures are checked).
func (v *Verifier) Enabled() bool { return v != nil && v.jwksURL != "" }

// Describe is a one-line startup log of the effective verification posture.
func (v *Verifier) Describe() string {
	if !v.Enabled() {
		return "auth: JWKS DISABLED (OPENFORT_JWKS_URL unset) — tokens are decoded, NOT verified. Dev/demo only."
	}
	return fmt.Sprintf("auth: JWKS enabled url=%s issuer=%q audience=%q ttl=%s",
		v.jwksURL, v.issuer, v.audience, v.ttl)
}

// jwtHeader is the decoded JOSE header we care about.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// fullClaims covers the registered claims we validate plus the profile bits the
// auth edge forwards to user-service.
type fullClaims struct {
	Sub   string `json:"sub"`
	Scope string `json:"scope"`
	Exp   int64  `json:"exp"`
	Nbf   int64  `json:"nbf"`
	Iat   int64  `json:"iat"`
	Iss   string `json:"iss"`
	Email string `json:"email"`
	// aud is a string OR an array of strings per RFC 7519 — decoded manually.
	Aud json.RawMessage `json:"aud"`
}

// Verify checks the signature, expiry, issuer and audience of a JWT and returns
// its claims. Requires Enabled(); callers should branch on that.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return nil, ErrMalformed
	}
	hash, err := hashForAlg(hdr.Alg)
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}

	key, err := v.keyFor(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}

	signed := parts[0] + "." + parts[1]
	digest := digestOf(hash, signed)
	if !verifySignature(key, hash, digest, sig) {
		// A rotated key can be cached-stale: force one refresh and retry before failing.
		if fresh, rErr := v.refreshAndGet(ctx, hdr.Kid); rErr == nil {
			if verifySignature(fresh, hash, digest, sig) {
				return v.claimsFrom(parts[1])
			}
		}
		return nil, ErrBadSignature
	}
	return v.claimsFrom(parts[1])
}

// claimsFrom decodes and validates the payload segment (exp/nbf/iss/aud).
func (v *Verifier) claimsFrom(payloadSeg string) (*Claims, error) {
	payload, err := base64.RawURLEncoding.DecodeString(payloadSeg)
	if err != nil {
		return nil, ErrMalformed
	}
	var fc fullClaims
	if err := json.Unmarshal(payload, &fc); err != nil {
		return nil, ErrMalformed
	}

	now := time.Now()
	if fc.Exp != 0 && now.Add(-clockSkew).Unix() >= fc.Exp {
		return nil, ErrExpired
	}
	if fc.Nbf != 0 && now.Add(clockSkew).Unix() < fc.Nbf {
		return nil, ErrNotYetValid
	}
	if v.issuer != "" && fc.Iss != v.issuer {
		return nil, ErrBadIssuer
	}
	if v.audience != "" && !audienceContains(fc.Aud, v.audience) {
		return nil, ErrBadAudience
	}

	return &Claims{
		Subject:  fc.Sub,
		Scope:    fc.Scope,
		Exp:      fc.Exp,
		Email:    fc.Email,
		Issuer:   fc.Iss,
		Verified: true,
	}, nil
}

// audienceContains handles `aud` being either a string or an array of strings.
func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == want
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// hashForAlg maps a JOSE alg to its digest. Only asymmetric signatures are
// allowed: HS* (HMAC) and "none" are rejected outright, because with HS256 anyone
// holding the *publishable* key could forge a token, and "none" is never valid.
//
// ES* matters in practice: Openfort's JWKS serves EC P-256 keys, so ES256 is the
// algorithm real Openfort access tokens actually use.
func hashForAlg(alg string) (crypto.Hash, error) {
	switch alg {
	case "RS256", "ES256":
		return crypto.SHA256, nil
	case "RS384", "ES384":
		return crypto.SHA384, nil
	case "RS512", "ES512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrBadAlgorithm, alg)
	}
}

// verifySignature dispatches on the key type rather than the header's alg, so a
// token cannot claim RS256 while pointing at an EC key (or vice versa) to slip
// past verification.
func verifySignature(key crypto.PublicKey, hash crypto.Hash, digest, sig []byte) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, hash, digest, sig) == nil

	case *ecdsa.PublicKey:
		// JWS encodes an ECDSA signature as the raw r||s pair, each padded to the
		// curve's byte size — NOT the ASN.1/DER form ecdsa.VerifyASN1 expects.
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return false
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(k, digest, r, s)

	default:
		return false
	}
}

func digestOf(h crypto.Hash, s string) []byte {
	switch h {
	case crypto.SHA384:
		d := sha512.Sum384([]byte(s))
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512([]byte(s))
		return d[:]
	default:
		d := sha256.Sum256([]byte(s))
		return d[:]
	}
}

// keyFor returns the cached key for kid, fetching the JWKS when the cache is
// empty, stale, or missing that kid.
func (v *Verifier) keyFor(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	fresh := time.Since(v.fetchedAt) < v.ttl
	// A single-key JWKS often omits `kid` in the token — accept the lone key.
	lone := len(v.keys) == 1 && kid == ""
	var only crypto.PublicKey
	if lone {
		for _, k := range v.keys {
			only = k
		}
	}
	v.mu.RUnlock()

	if lone && fresh {
		return only, nil
	}
	if ok && fresh {
		return key, nil
	}
	return v.refreshAndGet(ctx, kid)
}

// refreshAndGet fetches the JWKS and returns the key for kid.
func (v *Verifier) refreshAndGet(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	if len(v.keys) == 1 && kid == "" {
		for _, k := range v.keys {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%w: kid=%q", ErrUnknownKey, kid)
}

type jwksDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		// RSA
		N string `json:"n"`
		E string `json:"e"`
		// EC
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"keys"`
}

// refresh fetches + parses the JWKS. On failure the previous cache is kept (a
// transient IdP outage must not lock every user out mid-session).
func (v *Verifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSUnhealthy, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrJWKSUnhealthy, resp.StatusCode)
	}

	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSUnhealthy, err)
	}

	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		var (
			pub crypto.PublicKey
			err error
		)
		switch k.Kty {
		case "RSA":
			pub, err = rsaKeyFromJWK(k.N, k.E)
		case "EC":
			// Openfort's JWKS is EC P-256.
			pub, err = ecKeyFromJWK(k.Crv, k.X, k.Y)
		default:
			continue
		}
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: no usable RSA or EC signing keys", ErrJWKSUnhealthy)
	}

	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

// rsaKeyFromJWK rebuilds an RSA public key from the base64url modulus/exponent.
func rsaKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(nB64, "="))
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(eB64, "="))
	if err != nil {
		return nil, err
	}
	if len(nBytes) == 0 || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, errors.New("malformed JWK")
	}
	// Left-pad the exponent to 8 bytes so it decodes as a big-endian uint64.
	padded := make([]byte, 8)
	copy(padded[8-len(eBytes):], eBytes)
	e := binary.BigEndian.Uint64(padded)
	if e == 0 || e > 1<<31 {
		return nil, errors.New("malformed JWK exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e)}, nil
}

// ecKeyFromJWK rebuilds an ECDSA public key from a JWK's curve + affine
// coordinates. This is the path real Openfort tokens take (EC P-256 / ES256).
func ecKeyFromJWK(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", crv)
	}

	xb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(xB64, "="))
	if err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(yB64, "="))
	if err != nil {
		return nil, err
	}
	if len(xb) == 0 || len(yb) == 0 {
		return nil, errors.New("malformed EC JWK")
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
	// Reject a point that isn't actually on the curve — feeding an off-curve point
	// to ecdsa.Verify is not something to leave to chance.
	if !curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("EC JWK point is not on the curve")
	}
	return pub, nil
}
