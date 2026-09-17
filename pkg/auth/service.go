// Service-to-service identity for Everyflow's internal hops.
//
// WHY THIS EXISTS RATHER THAN AN IdP FLOW: Openfort has no machine-to-machine
// support — it issues per-user app access tokens and *static* secret API keys for
// calling Openfort's own API, but there is no client_credentials grant and no way
// to mint a per-service JWT our JWKS verifier could check. So Everyflow issues its
// own internal service tokens.
//
// WHY PER-SERVICE KEYPAIRS RATHER THAN ONE SHARED SECRET: with a shared symmetric
// secret every service can forge every other service's identity, so "market called
// recharge" would be unprovable and an authorization rule naming a caller would be
// worthless. Each service instead holds its OWN Ed25519 private key; only public
// keys are distributed, so a token naming `market` can only have been minted by
// whoever holds market's private key.
//
// Env:
//
//	SERVICE_NAME         this service's identity, e.g. "market"
//	SERVICE_PRIVATE_KEY  base64 (std or raw-url) 32-byte Ed25519 seed — SECRET, per service
//	SERVICE_PUBLIC_KEYS  JSON {"market":"<b64 pub>", "recharge":"<b64 pub>"} — public, same everywhere
package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ServiceIssuer marks a token as an internal service token. Inbound verification
// keys off this to choose the Ed25519 path over the Openfort JWKS path.
const ServiceIssuer = "everyflow-internal"

// serviceTokenTTL is deliberately short: these are minted on demand and cached in
// process, so there is no reason to hand out a long-lived internal credential.
const serviceTokenTTL = 5 * time.Minute

// refreshMargin re-mints before expiry so an in-flight call cannot age out.
const refreshMargin = 30 * time.Second

var (
	ErrNoServiceKey      = errors.New("SERVICE_PRIVATE_KEY not set")
	ErrNoServiceName     = errors.New("SERVICE_NAME not set")
	ErrUnknownService    = errors.New("no public key for service")
	ErrNotServiceToken   = errors.New("not an internal service token")
	ErrBadServiceKeyPair = errors.New("invalid ed25519 key material")
)

// decodeKey accepts standard or raw-url base64, with or without padding — env
// values get pasted between shells, CI and Infisical, and the variants differ.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, ErrBadServiceKeyPair
}

// GenerateServiceKeypair returns (base64 seed, base64 public key) for ops to put
// in Infisical and SERVICE_PUBLIC_KEYS respectively.
func GenerateServiceKeypair() (seedB64, pubB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()),
		base64.StdEncoding.EncodeToString(pub), nil
}

// ServiceName is this process's own identity.
func ServiceName() string { return strings.TrimSpace(os.Getenv("SERVICE_NAME")) }

// privateKeyFromEnv builds this service's signing key from its 32-byte seed.
func privateKeyFromEnv() (ed25519.PrivateKey, error) {
	raw := os.Getenv("SERVICE_PRIVATE_KEY")
	if strings.TrimSpace(raw) == "" {
		return nil, ErrNoServiceKey
	}
	seed, err := decodeKey(raw)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: seed is %d bytes, want %d", ErrBadServiceKeyPair, len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// publicKeysFromEnv parses the shared name -> public key map. Public material, so
// it is safe in a ConfigMap; the map is identical in every service.
func publicKeysFromEnv() (map[string]ed25519.PublicKey, error) {
	raw := strings.TrimSpace(os.Getenv("SERVICE_PUBLIC_KEYS"))
	if raw == "" {
		return map[string]ed25519.PublicKey{}, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("SERVICE_PUBLIC_KEYS is not valid JSON: %w", err)
	}
	out := make(map[string]ed25519.PublicKey, len(m))
	for name, b64 := range m {
		b, err := decodeKey(b64)
		if err != nil {
			return nil, fmt.Errorf("public key for %q: %w", name, err)
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("public key for %q is %d bytes, want %d", name, len(b), ed25519.PublicKeySize)
		}
		out[name] = ed25519.PublicKey(b)
	}
	return out, nil
}

// NewServiceToken mints an EdDSA JWT asserting `name`, valid for ttl.
func NewServiceToken(name string, priv ed25519.PrivateKey, ttl time.Duration) (string, error) {
	if name == "" {
		return "", ErrNoServiceName
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", ErrBadServiceKeyPair
	}
	now := time.Now()
	enc := func(v any) (string, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	h, err := enc(map[string]any{"alg": "EdDSA", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	p, err := enc(map[string]any{
		"iss": ServiceIssuer,
		"sub": name,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	})
	if err != nil {
		return "", err
	}
	signing := h + "." + p
	sig := ed25519.Sign(priv, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// serviceHeader/servicePayload mirror the fields we sign above.
type serviceHeader struct {
	Alg string `json:"alg"`
}
type servicePayload struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
}

// peekIssuer reads `iss` without verifying anything, so the interceptor can route
// a token to the right verifier. Never trust its output for authorization.
func peekIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var p servicePayload
	if json.Unmarshal(b, &p) != nil {
		return ""
	}
	return p.Iss
}

// VerifyServiceToken checks an internal service token against the public key of
// the service it names. Fails closed: unknown issuer, unknown service, wrong
// algorithm, bad signature and expiry are all rejected.
func VerifyServiceToken(token string, keys map[string]ed25519.PublicKey) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	var h serviceHeader
	if json.Unmarshal(hb, &h) != nil {
		return nil, ErrMalformed
	}
	// Pin the algorithm. Accepting whatever the token claims is how "alg: none"
	// and algorithm-confusion attacks get in.
	if h.Alg != "EdDSA" {
		return nil, ErrBadAlgorithm
	}

	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	var p servicePayload
	if json.Unmarshal(pb, &p) != nil {
		return nil, ErrMalformed
	}
	if p.Iss != ServiceIssuer {
		return nil, ErrNotServiceToken
	}
	if p.Sub == "" {
		return nil, ErrNoServiceName
	}
	pub, ok := keys[p.Sub]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownService, p.Sub)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, ErrBadSignature
	}

	now := time.Now()
	if p.Exp == 0 || now.After(time.Unix(p.Exp, 0).Add(clockSkew)) {
		return nil, ErrExpired
	}
	if p.Iat != 0 && now.Add(clockSkew).Before(time.Unix(p.Iat, 0)) {
		return nil, ErrNotYetValid
	}

	return &Claims{
		Subject:  p.Sub,
		Issuer:   p.Iss,
		Exp:      p.Exp,
		Verified: true, // signature was checked; there is no decode-only path here
		Service:  p.Sub,
	}, nil
}

// --- process-wide config, built once ---

var (
	svcOnce sync.Once
	svcPriv ed25519.PrivateKey
	svcName string
	svcKeys map[string]ed25519.PublicKey
	svcErr  error
)

func serviceConfig() (string, ed25519.PrivateKey, map[string]ed25519.PublicKey, error) {
	svcOnce.Do(func() {
		svcName = ServiceName()
		svcKeys, svcErr = publicKeysFromEnv()
		if svcErr != nil {
			return
		}
		// A missing private key is not fatal: a service that only *receives*
		// internal calls still needs the public map to verify them.
		if priv, err := privateKeyFromEnv(); err == nil {
			svcPriv = priv
		}
	})
	return svcName, svcPriv, svcKeys, svcErr
}

// ServicePublicKeys exposes the parsed verification map (nil on config error).
func ServicePublicKeys() map[string]ed25519.PublicKey {
	_, _, keys, err := serviceConfig()
	if err != nil {
		return nil
	}
	return keys
}

// DescribeService is a one-line startup log of the service-identity posture,
// mirroring Verifier.Describe() so both show up together in the pod logs.
func DescribeService() string {
	name, priv, keys, err := serviceConfig()
	if err != nil {
		return "auth: service identity MISCONFIGURED — " + err.Error()
	}
	switch {
	case name == "":
		return "auth: service identity OFF (SERVICE_NAME unset) — this service cannot make authenticated internal calls"
	case priv == nil:
		return fmt.Sprintf("auth: service identity name=%q signing=DISABLED (no SERVICE_PRIVATE_KEY) verify=%d peer key(s)", name, len(keys))
	default:
		return fmt.Sprintf("auth: service identity name=%q signing=enabled verify=%d peer key(s)", name, len(keys))
	}
}

// --- outbound: cached token for this service ---

var (
	tokMu     sync.Mutex
	tokCached string
	tokExpiry time.Time
)

// ServiceToken returns a short-lived token asserting this service's identity,
// minting a new one shortly before the cached one expires. Safe for concurrent use.
func ServiceToken() (string, error) {
	name, priv, _, err := serviceConfig()
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", ErrNoServiceName
	}
	if priv == nil {
		return "", ErrNoServiceKey
	}

	tokMu.Lock()
	defer tokMu.Unlock()
	if tokCached != "" && time.Now().Before(tokExpiry.Add(-refreshMargin)) {
		return tokCached, nil
	}
	tok, err := NewServiceToken(name, priv, serviceTokenTTL)
	if err != nil {
		return "", err
	}
	tokCached, tokExpiry = tok, time.Now().Add(serviceTokenTTL)
	return tok, nil
}
