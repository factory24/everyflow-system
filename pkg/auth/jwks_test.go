package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The verifier is the security boundary for the whole platform: if it accepts a
// forged token, every downstream service trusts the caller. These tests exercise
// it against a real RSA key and a real JWKS endpoint, offline.

const testKID = "test-key-1"

// jwksServer serves a JWKS containing pub, and counts how often it was fetched.
func jwksServer(t *testing.T, pub *rsa.PublicKey, kid string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// signToken builds a real RS256 JWT signed with key.
func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	signing := enc(header) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, 0x5, digest[:]) // 0x5 == crypto.SHA256
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func testVerifier(t *testing.T, jwksURL, issuer, audience string) *Verifier {
	t.Helper()
	return &Verifier{
		jwksURL:  jwksURL,
		issuer:   issuer,
		audience: audience,
		ttl:      10 * time.Minute,
		client:   &http.Client{Timeout: 5 * time.Second},
		keys:     map[string]crypto.PublicKey{},
	}
}

func validClaims() map[string]any {
	return map[string]any{
		"sub":   "openfort|user-123",
		"email": "investor@example.com",
		"scope": "user:basic",
		"iss":   "https://api.openfort.io",
		"aud":   "everyflow",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
}

func TestVerify_ValidToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := jwksServer(t, &key.PublicKey, testKID)
	v := testVerifier(t, srv.URL, "https://api.openfort.io", "everyflow")

	claims, err := v.Verify(context.Background(), signToken(t, key, testKID, validClaims()))
	if err != nil {
		t.Fatalf("expected valid token to verify, got %v", err)
	}
	if claims.Subject != "openfort|user-123" {
		t.Errorf("subject = %q, want openfort|user-123", claims.Subject)
	}
	if claims.Email != "investor@example.com" {
		t.Errorf("email = %q, want investor@example.com", claims.Email)
	}
	if !claims.Verified {
		t.Error("Verified must be true for a signature-checked token — the edge " +
			"uses this flag to tell a real session from a demo one")
	}
}

// The critical case: a token signed by a key that is NOT in the JWKS must be
// rejected. This is what stops anyone who can mint their own JWT.
func TestVerify_ForgedSignatureRejected(t *testing.T) {
	real, _ := rsa.GenerateKey(rand.Reader, 2048)
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)

	srv, _ := jwksServer(t, &real.PublicKey, testKID)
	v := testVerifier(t, srv.URL, "", "")

	// Same kid, so it resolves to the real key — but signed by the attacker.
	if _, err := v.Verify(context.Background(), signToken(t, attacker, testKID, validClaims())); err == nil {
		t.Fatal("SECURITY: a token signed by a non-JWKS key was accepted")
	}
}

func TestVerify_TamperedPayloadRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv, _ := jwksServer(t, &key.PublicKey, testKID)
	v := testVerifier(t, srv.URL, "", "")

	tok := signToken(t, key, testKID, validClaims())
	parts := strings.Split(tok, ".")
	// Swap the subject for an admin-looking one, keeping the original signature.
	forged := map[string]any{"sub": "openfort|admin", "exp": time.Now().Add(time.Hour).Unix()}
	b, _ := json.Marshal(forged)
	parts[1] = base64.RawURLEncoding.EncodeToString(b)

	if _, err := v.Verify(context.Background(), strings.Join(parts, ".")); err == nil {
		t.Fatal("SECURITY: a token with a tampered payload was accepted")
	}
}

// "alg":"none" and HMAC algorithms must never be honoured — with HS256 anyone
// holding the *publishable* key could use it as an HMAC secret to forge tokens.
// ES256 is deliberately NOT in this list: it is what Openfort actually uses.
func TestVerify_RejectsSymmetricAndNoneAlgorithms(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv, _ := jwksServer(t, &key.PublicKey, testKID)
	v := testVerifier(t, srv.URL, "", "")

	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	for _, alg := range []string{"none", "HS256", "HS384", "HS512", "PS256"} {
		tok := enc(map[string]any{"alg": alg, "typ": "JWT", "kid": testKID}) + "." +
			enc(validClaims()) + ".c2ln"
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Errorf("SECURITY: alg=%q was accepted", alg)
		}
	}
}

// ── EC / ES256: the algorithm real Openfort access tokens use ────────────────
//
// Openfort's JWKS (https://api.openfort.io/iam/v1/<pk>/jwks.json) serves EC P-256
// keys. An RSA-only verifier rejects every genuine Openfort token, so this path is
// the one that actually matters in production.

func ecJWKSServer(t *testing.T, pub *ecdsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	size := (pub.Curve.Params().BitSize + 7) / 8
	pad := func(b []byte) string {
		out := make([]byte, size)
		copy(out[size-len(b):], b)
		return base64.RawURLEncoding.EncodeToString(out)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "EC", "use": "sig", "alg": "ES256", "crv": "P-256",
				"kid": kid,
				"x":   pad(pub.X.Bytes()),
				"y":   pad(pub.Y.Bytes()),
			}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// signES256 builds a real ES256 JWT. The JWS signature is the raw r||s pair, each
// left-padded to the curve size — not ASN.1/DER.
func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	signing := enc(header) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	size := 32 // P-256
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerify_ES256Token(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := ecJWKSServer(t, &key.PublicKey, testKID)
	v := testVerifier(t, srv.URL, "https://api.openfort.io", "everyflow")

	claims, err := v.Verify(context.Background(), signES256(t, key, testKID, validClaims()))
	if err != nil {
		t.Fatalf("a valid ES256 token must verify (this is what Openfort issues), got %v", err)
	}
	if claims.Subject != "openfort|user-123" || !claims.Verified {
		t.Errorf("claims = %+v", claims)
	}
}

func TestVerify_ES256ForgedRejected(t *testing.T) {
	real, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := ecJWKSServer(t, &real.PublicKey, testKID)
	v := testVerifier(t, srv.URL, "", "")

	if _, err := v.Verify(context.Background(), signES256(t, attacker, testKID, validClaims())); err == nil {
		t.Fatal("SECURITY: an ES256 token signed by a non-JWKS key was accepted")
	}
}

// A DER-encoded signature must be rejected: JWS mandates raw r||s, and silently
// accepting DER would mean accepting malleable signature encodings.
func TestVerify_ES256RejectsDERSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := ecJWKSServer(t, &key.PublicKey, testKID)
	v := testVerifier(t, srv.URL, "", "")

	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(map[string]any{"alg": "ES256", "typ": "JWT", "kid": testKID}) + "." + enc(validClaims())
	digest := sha256.Sum256([]byte(signing))
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	tok := signing + "." + base64.RawURLEncoding.EncodeToString(der)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("a DER-encoded ECDSA signature was accepted; JWS requires raw r||s")
	}
}

// An EC point that is not on the curve must never make it into the key cache.
func TestVerify_RejectsOffCurveECKey(t *testing.T) {
	if _, err := ecKeyFromJWK("P-256",
		base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
		base64.RawURLEncoding.EncodeToString([]byte{4, 5, 6})); err == nil {
		t.Fatal("SECURITY: an off-curve EC point was accepted as a signing key")
	}
}

func TestVerify_ExpiredAndIssuerAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv, _ := jwksServer(t, &key.PublicKey, testKID)

	t.Run("expired", func(t *testing.T) {
		v := testVerifier(t, srv.URL, "", "")
		c := validClaims()
		// Beyond the 60s clock-skew allowance.
		c["exp"] = time.Now().Add(-5 * time.Minute).Unix()
		if _, err := v.Verify(context.Background(), signToken(t, key, testKID, c)); err != ErrExpired {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})

	t.Run("clock skew tolerated", func(t *testing.T) {
		v := testVerifier(t, srv.URL, "", "")
		c := validClaims()
		// Just expired: a few seconds of IdP/service drift must not log users out.
		c["exp"] = time.Now().Add(-5 * time.Second).Unix()
		if _, err := v.Verify(context.Background(), signToken(t, key, testKID, c)); err != nil {
			t.Fatalf("a token %ds past exp should be tolerated, got %v", 5, err)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		v := testVerifier(t, srv.URL, "https://expected.example", "")
		if _, err := v.Verify(context.Background(), signToken(t, key, testKID, validClaims())); err != ErrBadIssuer {
			t.Fatalf("err = %v, want ErrBadIssuer", err)
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		v := testVerifier(t, srv.URL, "", "some-other-app")
		if _, err := v.Verify(context.Background(), signToken(t, key, testKID, validClaims())); err != ErrBadAudience {
			t.Fatalf("err = %v, want ErrBadAudience", err)
		}
	})

	// RFC 7519 allows aud to be an array; a member match must pass.
	t.Run("audience array", func(t *testing.T) {
		v := testVerifier(t, srv.URL, "", "everyflow")
		c := validClaims()
		c["aud"] = []string{"other", "everyflow"}
		if _, err := v.Verify(context.Background(), signToken(t, key, testKID, c)); err != nil {
			t.Fatalf("aud array containing the expected value should pass, got %v", err)
		}
	})
}

// Keys must be cached: re-fetching the JWKS on every request would add a network
// round trip to every authenticated call.
func TestVerify_CachesJWKS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv, hits := jwksServer(t, &key.PublicKey, testKID)
	v := testVerifier(t, srv.URL, "", "")

	for i := 0; i < 5; i++ {
		if _, err := v.Verify(context.Background(), signToken(t, key, testKID, validClaims())); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("JWKS fetched %d times for 5 verifications, want 1 (cache not working)", got)
	}
}

// A single-key JWKS is common and such tokens often omit `kid`.
func TestVerify_NoKidSingleKeyJWKS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv, _ := jwksServer(t, &key.PublicKey, "")
	v := testVerifier(t, srv.URL, "", "")

	if _, err := v.Verify(context.Background(), signToken(t, key, "", validClaims())); err != nil {
		t.Fatalf("token without kid against a single-key JWKS should verify, got %v", err)
	}
}

func TestVerify_UnreachableJWKSFailsClosed(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	// A port nothing listens on.
	v := testVerifier(t, "http://127.0.0.1:1/jwks.json", "", "")

	if _, err := v.Verify(context.Background(), signToken(t, key, testKID, validClaims())); err == nil {
		t.Fatal("SECURITY: verification succeeded with an unreachable JWKS — must fail closed")
	}
}

func TestEnabled_AndDescribe(t *testing.T) {
	if (&Verifier{}).Enabled() {
		t.Error("a verifier with no JWKS URL must report Enabled() == false")
	}
	if !strings.Contains((&Verifier{}).Describe(), "DISABLED") {
		t.Error("Describe must make a disabled verifier obvious in the startup log")
	}
}

// VerifyOrDecode must fall back to decode-only when no JWKS is configured, and the
// resulting claims must NOT be marked Verified.
func TestVerifyOrDecode_FallbackIsNotVerified(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := signToken(t, key, testKID, validClaims())

	claims, err := ValidateToken(tok)
	if err != nil {
		t.Fatalf("decode path: %v", err)
	}
	if claims.Verified {
		t.Error("decode-only claims must have Verified == false, otherwise a demo " +
			"session is indistinguishable from a verified one")
	}
	if claims.Subject != "openfort|user-123" {
		t.Errorf("subject = %q", claims.Subject)
	}
}
