package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// makeToken builds a fake unsigned JWT (header.payload.sig) for testing the
// claim-decode + exp logic. Signature is not verified by the stub.
func makeToken(claims map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]any{"alg": "RS256", "typ": "JWT"}) + "." + enc(claims) + ".sig"
}

func TestValidateToken_Valid(t *testing.T) {
	tok := makeToken(map[string]any{
		"sub":   "openfort-user-123",
		"scope": "user:basic",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	c, err := ValidateToken(tok)
	if err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
	if c.Subject != "openfort-user-123" || c.Scope != "user:basic" {
		t.Fatalf("bad claims: %+v", c)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	tok := makeToken(map[string]any{"sub": "x", "exp": time.Now().Add(-time.Minute).Unix()})
	if _, err := ValidateToken(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestValidateToken_Malformed(t *testing.T) {
	for _, bad := range []string{"", "not-a-jwt", "only.two", "a.!!!.c"} {
		if _, err := ValidateToken(bad); !errors.Is(err, ErrMalformed) {
			t.Fatalf("token %q: expected ErrMalformed, got %v", bad, err)
		}
	}
}
