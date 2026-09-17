package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
)

// The JWKS tests cover whether a signature is good. These cover the gate itself:
// which requests Interceptor() lets past. That decision is what stood between the
// public internet and the user table, and nothing exercised it.

// callInterceptor runs Interceptor() over a no-op handler with the given
// Authorization header, reporting whether the handler ran and what claims (if
// any) reached it.
func callInterceptor(t *testing.T, authzHeader string) (reached bool, claims *Claims, err error) {
	t.Helper()

	next := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		reached = true
		if c, ok := FromContext(ctx); ok {
			claims = c
		}
		return connect.NewResponse(&struct{}{}), nil
	}

	req := connect.NewRequest(&struct{}{})
	if authzHeader != "" {
		req.Header().Set("Authorization", authzHeader)
	}

	_, err = Interceptor()(next)(context.Background(), req)
	return reached, claims, err
}

func TestInterceptor_NoToken_PermissiveByDefault(t *testing.T) {
	t.Setenv("AUTH_REQUIRE_TOKEN", "")

	reached, claims, err := callInterceptor(t, "")
	if err != nil {
		t.Fatalf("expected the request to pass through, got %v", err)
	}
	if !reached {
		t.Fatal("handler was not reached")
	}
	if claims != nil {
		t.Fatalf("no token was sent, so no claims should be attached, got %+v", claims)
	}
}

// The behaviour the cluster will depend on once AUTH_REQUIRE_TOKEN is turned on.
func TestInterceptor_NoToken_RejectedWhenRequired(t *testing.T) {
	t.Setenv("AUTH_REQUIRE_TOKEN", "true")

	reached, _, err := callInterceptor(t, "")
	if err == nil {
		t.Fatal("expected an unauthenticated error, got nil")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("expected CodeUnauthenticated, got %v", got)
	}
	if reached {
		t.Fatal("handler ran despite a missing token")
	}
}

// A bad token must be refused whether or not tokens are mandatory — otherwise the
// permissive default would silently accept garbage.
func TestInterceptor_BadTokenRejectedInBothModes(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{"malformed", "Bearer not-a-jwt"},
		{"expired", "Bearer " + makeToken(map[string]any{
			"sub": "u1", "exp": time.Now().Add(-time.Hour).Unix(),
		})},
	}

	for _, required := range []string{"", "true"} {
		for _, tc := range cases {
			t.Run(tc.name+"/require="+required, func(t *testing.T) {
				t.Setenv("AUTH_REQUIRE_TOKEN", required)

				reached, _, err := callInterceptor(t, tc.header)
				if err == nil {
					t.Fatal("expected the token to be refused, got nil error")
				}
				if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
					t.Fatalf("expected CodeUnauthenticated, got %v", got)
				}
				if reached {
					t.Fatal("handler ran on a bad token")
				}
			})
		}
	}
}

func TestInterceptor_ValidTokenReachesHandlerWithClaims(t *testing.T) {
	if DefaultVerifier().Enabled() {
		// A JWKS URL is configured process-wide (DefaultVerifier is a sync.Once),
		// so an unsigned test token cannot pass. The decode-only path is covered
		// by ValidateToken's own tests.
		t.Skip("JWKS verification is enabled in this process; skipping decode-only case")
	}
	t.Setenv("AUTH_REQUIRE_TOKEN", "true")

	tok := makeToken(map[string]any{
		"sub":   "openfort-user-123",
		"scope": "user:basic",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	reached, claims, err := callInterceptor(t, "Bearer "+tok)
	if err != nil {
		t.Fatalf("expected the token to be accepted, got %v", err)
	}
	if !reached {
		t.Fatal("handler was not reached")
	}
	if claims == nil {
		t.Fatal("claims were not attached to the context")
	}
	if claims.Subject != "openfort-user-123" {
		t.Fatalf("wrong subject: %+v", claims)
	}
	if claims.Verified {
		t.Fatal("decode-only claims must not report Verified=true")
	}
}

// "bearer" is case-insensitive per RFC 6750; a client sending lowercase must not
// be treated as unauthenticated.
func TestInterceptor_BearerPrefixIsCaseInsensitive(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "bearer abc.def.ghi")
	if got := BearerToken(h); got != "abc.def.ghi" {
		t.Fatalf("lowercase bearer not accepted, got %q", got)
	}
}
