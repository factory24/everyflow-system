package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

func callProcedure(t *testing.T, procedure, authzHeader string) (bool, error) {
	t.Helper()
	reached := false
	next := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		reached = true
		return connect.NewResponse(&struct{}{}), nil
	}
	req := &procReq{Request: connect.NewRequest(&struct{}{}), proc: procedure}
	if authzHeader != "" {
		req.Header().Set("Authorization", authzHeader)
	}
	_, err := Interceptor()(next)(context.Background(), req)
	return reached, err
}

type procReq struct {
	*connect.Request[struct{}]
	proc string
}

func (r *procReq) Spec() connect.Spec { return connect.Spec{Procedure: r.proc} }

func TestInterceptor_RequireWrites(t *testing.T) {
	t.Setenv("AUTH_REQUIRE_TOKEN", "")
	t.Setenv("AUTH_REQUIRE_WRITES", "true")
	valid := "Bearer " + makeToken(map[string]any{"sub": "u1", "exp": time.Now().Add(time.Hour).Unix()})

	for _, proc := range []string{"/recharge.v1.RechargeService/RecordRecharge", "/market.v1.MarketService/Buy", "/token.v1.TokenService/MintNft"} {
		if reached, err := callProcedure(t, proc, ""); connect.CodeOf(err) != connect.CodeUnauthenticated || reached {
			t.Fatalf("%s anonymous: want Unauthenticated, got err=%v reached=%v", proc, err, reached)
		}
		if reached, err := callProcedure(t, proc, valid); err != nil || !reached {
			t.Fatalf("%s signed-in: want pass, got err=%v reached=%v", proc, err, reached)
		}
	}
	for _, proc := range []string{"/recharge.v1.RechargeService/ListVaults", "/market.v1.MarketService/GetPoolTerms", "/market.v1.MarketService/Quote"} {
		if reached, err := callProcedure(t, proc, ""); err != nil || !reached {
			t.Fatalf("%s anonymous read: want pass, got err=%v reached=%v", proc, err, reached)
		}
	}
}

func TestInterceptor_RequireWrites_ServiceSecretAndListUsers(t *testing.T) {
	t.Setenv("AUTH_REQUIRE_TOKEN", "")
	t.Setenv("AUTH_REQUIRE_WRITES", "true")
	t.Setenv("EVERYFLOW_SERVICE_SECRET", "s3cret")

	if reached, err := callProcedure(t, "/user.v1.UserService/ListUsers", ""); connect.CodeOf(err) != connect.CodeUnauthenticated || reached {
		t.Fatalf("anonymous ListUsers: want Unauthenticated, got err=%v reached=%v", err, reached)
	}

	run := func(secret string) (bool, error) {
		reached := false
		next := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			reached = true
			return connect.NewResponse(&struct{}{}), nil
		}
		req := &procReq{Request: connect.NewRequest(&struct{}{}), proc: "/recharge.v1.RechargeService/RecordRecharge"}
		if secret != "" {
			req.Header().Set("X-Everyflow-Service-Secret", secret)
		}
		_, err := Interceptor()(next)(context.Background(), req)
		return reached, err
	}
	if reached, err := run("s3cret"); err != nil || !reached {
		t.Fatalf("service secret: want pass, got err=%v reached=%v", err, reached)
	}
	if reached, err := run("wrong"); connect.CodeOf(err) != connect.CodeUnauthenticated || reached {
		t.Fatalf("wrong secret: want Unauthenticated, got err=%v reached=%v", err, reached)
	}
}

// An Openfort outage is "could not check the token", not "the token is bad": the caller gets Unavailable
// (HTTP 503), is not told they are signed out, and a token Openfort actually refuses is still Unauthenticated.
func TestInterceptor_OpaqueOutageIsUnavailableNotUnauthenticated(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{opaqueToken: {"usr_1", "a@x.io"}})
	useOpenfort(t, f)

	for _, status := range []int32{http.StatusBadGateway, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		f.status.Store(status)
		resetOpaqueCache()
		reached, _, err := callInterceptor(t, "Bearer "+opaqueToken)
		if err == nil || connect.CodeOf(err) != connect.CodeUnavailable || reached {
			t.Errorf("openfort %d: err=%v reached=%v, want Unavailable and the handler not run", status, err, reached)
		}
	}

	f.status.Store(http.StatusUnauthorized) // Openfort answers, and says no
	resetOpaqueCache()
	if _, _, err := callInterceptor(t, "Bearer "+opaqueToken); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("a token Openfort refuses must stay Unauthenticated, got %v", err)
	}

	f.status.Store(0) // recovered, and the token is good
	resetOpaqueCache()
	if reached, _, err := callInterceptor(t, "Bearer "+opaqueToken); err != nil || !reached {
		t.Errorf("after recovery: err=%v reached=%v", err, reached)
	}
}

// Openfort unreachable at the network level (not just a 5xx) is the same outage.
func TestInterceptor_OpaqueUnreachableIsUnavailable(t *testing.T) {
	f := newFakeOpenfort(t, nil)
	useOpenfort(t, f)
	f.Close() // nothing is listening any more
	resetOpaqueCache()
	if _, _, err := callInterceptor(t, "Bearer "+opaqueToken); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("an unreachable Openfort must be Unavailable, got %v", err)
	}
}

func TestIsUnavailableAndConnectError(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want connect.Code
	}{
		{"opaque outage", fmt.Errorf("%w: boom", ErrOpaqueUnavailable), connect.CodeUnavailable},
		{"opaque outage, wrapped again", errors.Join(errors.New("ctx"), fmt.Errorf("%w: boom", ErrOpaqueUnavailable)), connect.CodeUnavailable},
		{"jwks fetch failed", fmt.Errorf("%w: status 500", ErrJWKSUnhealthy), connect.CodeUnavailable},
		{"opaque rejected", ErrOpaqueRejected, connect.CodeUnauthenticated},
		{"bad signature", ErrBadSignature, connect.CodeUnauthenticated},
		{"unknown kid", ErrUnknownKey, connect.CodeUnauthenticated},
		{"plain error", errors.New("malformed token"), connect.CodeUnauthenticated},
	} {
		if got := connect.CodeOf(ConnectError(c.err)); got != c.want {
			t.Errorf("%s: code %v, want %v", c.name, got, c.want)
		}
		if IsUnavailable(c.err) != (c.want == connect.CodeUnavailable) {
			t.Errorf("%s: IsUnavailable = %v", c.name, IsUnavailable(c.err))
		}
	}
}

// The caller of an outage gets a plain message: Openfort's URL and the socket error stay in the log.
func TestConnectError_UnavailableHidesTheCause(t *testing.T) {
	cause := fmt.Errorf("%w: Get \"http://10.1.2.3:9911/iam/v2/me\": dial tcp 10.1.2.3:9911: connection refused", ErrOpaqueUnavailable)
	ce := ConnectError(cause)
	if connect.CodeOf(ce) != connect.CodeUnavailable {
		t.Fatalf("code = %v, want unavailable", connect.CodeOf(ce))
	}
	msg := ce.Message()
	for _, leak := range []string{"10.1.2.3", "9911", "iam/v2/me", "dial tcp", "connection refused", "openfort"} {
		if strings.Contains(strings.ToLower(msg), leak) {
			t.Errorf("message %q leaks %q", msg, leak)
		}
	}
	if !errors.Is(ce.Unwrap(), ErrVerifierUnavailable) {
		t.Errorf("message = %q, want it to be ErrVerifierUnavailable", msg)
	}
	// A refusal still explains itself (it is the caller's own bad token).
	if got := ConnectError(ErrOpaqueRejected).Message(); got == "" {
		t.Errorf("a refusal should keep its reason")
	}
}
