package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
)

// keyring builds n named services with fresh keypairs, returning the private keys
// and the public map a receiver would be configured with.
func keyring(t *testing.T, names ...string) (map[string]ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	t.Helper()
	privs := map[string]ed25519.PrivateKey{}
	pubs := map[string]ed25519.PublicKey{}
	for _, n := range names {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		privs[n], pubs[n] = priv, pub
	}
	return privs, pubs
}

func TestServiceToken_RoundTrip(t *testing.T) {
	privs, pubs := keyring(t, "market", "recharge")

	tok, err := NewServiceToken("market", privs["market"], time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	claims, err := VerifyServiceToken(tok, pubs)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Service != "market" || claims.Subject != "market" {
		t.Fatalf("wrong identity: %+v", claims)
	}
	if !claims.IsService() {
		t.Fatal("IsService() should be true")
	}
	if !claims.Verified {
		t.Fatal("a service token is always signature-checked; Verified must be true")
	}
}

// The whole point of per-service keypairs: holding one service's key must not let
// you speak as another. A shared secret would fail this test.
func TestServiceToken_CannotImpersonateAnotherService(t *testing.T) {
	privs, pubs := keyring(t, "market", "recharge")

	// market signs a token that CLAIMS to be recharge.
	forged, err := NewServiceToken("recharge", privs["market"], time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, err := VerifyServiceToken(forged, pubs); err == nil {
		t.Fatal("market forged a token as recharge and it was accepted")
	}
}

func TestServiceToken_UnknownServiceRejected(t *testing.T) {
	privs, _ := keyring(t, "ghost")
	_, pubs := keyring(t, "market")

	tok, _ := NewServiceToken("ghost", privs["ghost"], time.Minute)
	if _, err := VerifyServiceToken(tok, pubs); err == nil {
		t.Fatal("a service with no registered public key was accepted")
	}
}

func TestServiceToken_ExpiredRejected(t *testing.T) {
	privs, pubs := keyring(t, "market")

	tok, _ := NewServiceToken("market", privs["market"], -2*clockSkew)
	if _, err := VerifyServiceToken(tok, pubs); err == nil {
		t.Fatal("an expired service token was accepted")
	}
}

func TestServiceToken_TamperedPayloadRejected(t *testing.T) {
	privs, pubs := keyring(t, "market", "recharge")
	tok, _ := NewServiceToken("market", privs["market"], time.Minute)

	parts := strings.Split(tok, ".")
	var p map[string]any
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(raw, &p)
	p["sub"] = "recharge" // escalate to a different service
	nb, _ := json.Marshal(p)
	parts[1] = base64.RawURLEncoding.EncodeToString(nb)

	if _, err := VerifyServiceToken(strings.Join(parts, "."), pubs); err == nil {
		t.Fatal("payload was rewritten and the token still verified")
	}
}

// alg-confusion / alg:none must be refused outright rather than trusted.
func TestServiceToken_RejectsNonEdDSAAlgorithm(t *testing.T) {
	_, pubs := keyring(t, "market")

	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	for _, alg := range []string{"none", "HS256", "RS256"} {
		tok := enc(map[string]any{"alg": alg, "typ": "JWT"}) + "." +
			enc(map[string]any{
				"iss": ServiceIssuer, "sub": "market",
				"exp": time.Now().Add(time.Minute).Unix(),
			}) + "."
		if _, err := VerifyServiceToken(tok, pubs); err == nil {
			t.Fatalf("alg=%q was accepted", alg)
		}
	}
}

// A user token must never be mistaken for a service token, and vice versa.
func TestServiceToken_UserTokenIsNotAServiceToken(t *testing.T) {
	_, pubs := keyring(t, "market")

	userTok := makeToken(map[string]any{
		"sub": "openfort-user-1",
		"iss": "https://openfort.example",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := VerifyServiceToken(userTok, pubs); err == nil {
		t.Fatal("a user token verified as a service token")
	}
	if peekIssuer(userTok) == ServiceIssuer {
		t.Fatal("user token was routed to the service path")
	}
}

func TestKeypairEncodingRoundTrip(t *testing.T) {
	seed, pub, err := GenerateServiceKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	t.Setenv("SERVICE_NAME", "market")
	t.Setenv("SERVICE_PRIVATE_KEY", seed)
	t.Setenv("SERVICE_PUBLIC_KEYS", `{"market":"`+pub+`"}`)

	priv, err := privateKeyFromEnv()
	if err != nil {
		t.Fatalf("private key from env: %v", err)
	}
	keys, err := publicKeysFromEnv()
	if err != nil {
		t.Fatalf("public keys from env: %v", err)
	}

	tok, err := NewServiceToken("market", priv, time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := VerifyServiceToken(tok, keys); err != nil {
		t.Fatalf("env-configured round trip failed: %v", err)
	}
}

// Fail closed: a service token arriving where no public keys are configured must
// be rejected, never waved through.
func TestVerifyOrDecode_ServiceTokenWithNoKeysFailsClosed(t *testing.T) {
	privs, _ := keyring(t, "market")
	tok, _ := NewServiceToken("market", privs["market"], time.Minute)

	t.Setenv("SERVICE_PUBLIC_KEYS", "")
	// serviceConfig() is a sync.Once; if another test already populated it this
	// assertion is not meaningful, so only assert when the map really is empty.
	if len(ServicePublicKeys()) != 0 {
		t.Skip("service keys already configured in this process")
	}
	if _, err := VerifyOrDecode(context.Background(), tok); err == nil {
		t.Fatal("service token accepted with no verification keys configured")
	}
}

// A service caller's token must NOT be propagated onward — the next hop should
// see this service's identity, not the previous caller's.
func TestInterceptor_DoesNotPropagateServiceToken(t *testing.T) {
	privs, pubs := keyring(t, "market")
	t.Setenv("AUTH_REQUIRE_TOKEN", "true")

	tok, _ := NewServiceToken("market", privs["market"], time.Minute)
	claims, err := VerifyServiceToken(tok, pubs)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	ctx := NewContext(context.Background(), claims)
	if !claims.IsService() {
		t.Fatal("expected service claims")
	}
	if _, ok := TokenFromContext(ctx); ok {
		t.Fatal("a service token must not be stored for propagation")
	}
}

// The user's token IS forwarded, so downstream per-user rules still apply.
func TestClientInterceptor_ForwardsUserTokenOverServiceIdentity(t *testing.T) {
	seed, pub, _ := GenerateServiceKeypair()
	t.Setenv("SERVICE_NAME", "market")
	t.Setenv("SERVICE_PRIVATE_KEY", seed)
	t.Setenv("SERVICE_PUBLIC_KEYS", `{"market":"`+pub+`"}`)

	var seen string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		seen = req.Header().Get("Authorization")
		return connect.NewResponse(&struct{}{}), nil
	}

	ctx := NewTokenContext(context.Background(), "user-token-abc")
	req := connect.NewRequest(&struct{}{})
	if _, err := ClientInterceptor()(next)(ctx, req); err != nil {
		t.Fatalf("call: %v", err)
	}
	if seen != "Bearer user-token-abc" {
		t.Fatalf("expected the user's token to be forwarded, got %q", seen)
	}
}

func TestClientInterceptor_NeverOverwritesAnExplicitHeader(t *testing.T) {
	var seen string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		seen = req.Header().Get("Authorization")
		return connect.NewResponse(&struct{}{}), nil
	}

	req := connect.NewRequest(&struct{}{})
	req.Header().Set("Authorization", "Bearer explicit")
	ctx := NewTokenContext(context.Background(), "user-token-abc")

	if _, err := ClientInterceptor()(next)(ctx, req); err != nil {
		t.Fatalf("call: %v", err)
	}
	if seen != "Bearer explicit" {
		t.Fatalf("explicit header was overwritten, got %q", seen)
	}
}
