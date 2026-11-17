package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
)

// opaqueToken is shaped like the real thing: ~80 characters, no dots.
const opaqueToken = "Qn3xV8mTz0LpA7sHkR2cYdWfGj5uBe9oNiXtC4vZ1aMq6SrKyE8hJlPdUwOb3FgTnVxA2cYzDeLm"

// fakeOpenfort answers GET /iam/v2/me. tokens maps accepted token → (id,email); anything else is 401.
type fakeOpenfort struct {
	*httptest.Server
	hits    atomic.Int32
	status  atomic.Int32 // when non-zero, every call returns this status
	lastKey atomic.Value // x-project-key of the last call
	lastTok atomic.Value // bearer token of the last call

	unverified sync.Map    // tokens whose email Openfort reports as NOT verified
	omitFlag   atomic.Bool // answer without an emailVerified field at all
}

func newFakeOpenfort(t *testing.T, tokens map[string][2]string) *fakeOpenfort {
	t.Helper()
	f := &fakeOpenfort{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.lastKey.Store(r.Header.Get("x-project-key"))
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.lastTok.Store(tok)
		if r.URL.Path != "/iam/v2/me" {
			http.NotFound(w, r)
			return
		}
		if s := int(f.status.Load()); s != 0 {
			http.Error(w, "forced", s)
			return
		}
		who, ok := tokens[tok]
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body := map[string]any{"id": who[0]}
		if who[1] != "" {
			body["email"] = who[1]
		}
		if !f.omitFlag.Load() {
			_, unv := f.unverified.Load(tok)
			body["emailVerified"] = !unv
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(f.Close)
	return f
}

// useOpenfort points the resolver at the fake and identifies a project, then clears the cache.
func useOpenfort(t *testing.T, f *fakeOpenfort) {
	t.Helper()
	t.Setenv("OPENFORT_API_BASE_URL", f.URL)
	t.Setenv("OPENFORT_PUBLISHABLE_KEY", "pk_test_unit")
	t.Setenv("OPENFORT_JWKS_URL", "")
	t.Setenv("OPENFORT_OPAQUE_TOKENS", "")
	resetOpaqueCache()
	t.Cleanup(resetOpaqueCache)
}

func TestOpaque_ResolvesToVerifiedClaims(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{opaqueToken: {"usr_abc123", "admin@everyflow.io"}})
	useOpenfort(t, f)

	c, err := VerifyOrDecode(context.Background(), opaqueToken)
	if err != nil {
		t.Fatalf("opaque token should resolve: %v", err)
	}
	if c.Subject != "usr_abc123" || c.Email != "admin@everyflow.io" || !c.Verified {
		t.Errorf("claims = %+v, want subject usr_abc123, the email, Verified=true", c)
	}
	if got := f.lastTok.Load(); got != opaqueToken {
		t.Errorf("Openfort was asked with a different token than the caller's")
	}
	if got := f.lastKey.Load(); got != "pk_test_unit" {
		t.Errorf("x-project-key = %v, want pk_test_unit", got)
	}
}

func TestOpaque_UnknownTokenIsRejected(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{})
	useOpenfort(t, f)

	_, err := VerifyOrDecode(context.Background(), opaqueToken)
	if !errors.Is(err, ErrOpaqueRejected) {
		t.Fatalf("err = %v, want ErrOpaqueRejected", err)
	}
}

// One lookup per minute per token, not one per RPC.
func TestOpaque_SuccessIsCached(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{opaqueToken: {"usr_1", "a@x.io"}})
	useOpenfort(t, f)

	for i := 0; i < 5; i++ {
		if _, err := VerifyOrDecode(context.Background(), opaqueToken); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.hits.Load(); n != 1 {
		t.Errorf("Openfort hit %d times for 5 calls, want 1 (cached)", n)
	}
}

// A rejected token is remembered briefly so a bad client can't turn every request into an upstream call.
func TestOpaque_RejectionIsBrieflyCached(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{})
	useOpenfort(t, f)

	for i := 0; i < 4; i++ {
		_, _ = VerifyOrDecode(context.Background(), opaqueToken)
	}
	if n := f.hits.Load(); n != 1 {
		t.Errorf("Openfort hit %d times for 4 rejected calls, want 1", n)
	}
}

// An Openfort outage must not be remembered as "this user's token is bad".
func TestOpaque_TransientFailureIsNeverCached(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{opaqueToken: {"usr_1", "a@x.io"}})
	useOpenfort(t, f)
	f.status.Store(http.StatusBadGateway)

	_, err := VerifyOrDecode(context.Background(), opaqueToken)
	if !errors.Is(err, ErrOpaqueUnavailable) {
		t.Fatalf("err = %v, want ErrOpaqueUnavailable", err)
	}

	f.status.Store(0) // Openfort recovers
	c, err := VerifyOrDecode(context.Background(), opaqueToken)
	if err != nil || c.Subject != "usr_1" {
		t.Fatalf("after recovery: c=%+v err=%v — the outage was cached", c, err)
	}
}

func TestOpaque_MissingEmailStillResolves(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{opaqueToken: {"usr_noemail", ""}})
	useOpenfort(t, f)

	c, err := VerifyOrDecode(context.Background(), opaqueToken)
	if err != nil || c.Subject != "usr_noemail" || c.Email != "" || !c.Verified {
		t.Fatalf("c=%+v err=%v", c, err)
	}
}

// ── Configuration ────────────────────────────────────────────────────────────

func TestOpaque_ProjectKeyIsDerivedFromTheJWKSURL(t *testing.T) {
	t.Setenv("OPENFORT_PUBLISHABLE_KEY", "")
	t.Setenv("OPENFORT_JWKS_URL", "https://api.openfort.io/iam/v1/pk_test_derived-123/jwks.json")
	if got := opaqueProjectKey(); got != "pk_test_derived-123" {
		t.Errorf("derived key = %q", got)
	}
	// An explicit key wins.
	t.Setenv("OPENFORT_PUBLISHABLE_KEY", "pk_test_explicit")
	if got := opaqueProjectKey(); got != "pk_test_explicit" {
		t.Errorf("explicit key = %q", got)
	}
}

// With no project identified the feature stays off and behaviour is exactly what it was before.
func TestOpaque_OffWithoutAProject_RejectsAsMalformed(t *testing.T) {
	t.Setenv("OPENFORT_PUBLISHABLE_KEY", "")
	t.Setenv("OPENFORT_JWKS_URL", "")
	if OpaqueEnabled() {
		t.Fatal("OpaqueEnabled with no project configured")
	}
	if _, err := VerifyOrDecode(context.Background(), opaqueToken); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (unchanged behaviour)", err)
	}
}

func TestOpaque_KillSwitch(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{opaqueToken: {"usr_1", "a@x.io"}})
	useOpenfort(t, f)
	t.Setenv("OPENFORT_OPAQUE_TOKENS", "off")

	if _, err := VerifyOrDecode(context.Background(), opaqueToken); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed with the switch off", err)
	}
	if n := f.hits.Load(); n != 0 {
		t.Errorf("Openfort was contacted %d times with the feature switched off", n)
	}
}

// ── What must NOT go through Openfort ────────────────────────────────────────

func unsignedJWT(email string) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." +
		enc(map[string]any{"sub": "x", "email": email, "exp": 4102444800}) + "."
}

// JWT-shaped tokens keep their existing path. A forged one is not "verified", and it must never
// be able to borrow the Openfort lookup's Verified=true.
func TestOpaque_JWTShapedTokensNeverUseTheLookup(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{})
	useOpenfort(t, f)

	c, err := VerifyOrDecode(context.Background(), unsignedJWT("admin@everyflow.io"))
	if err == nil && c.Verified {
		t.Fatal("a forged JWT came back Verified")
	}
	if n := f.hits.Load(); n != 0 {
		t.Errorf("a JWT-shaped token triggered %d Openfort lookups, want 0", n)
	}
}

// Two dots means JWT-shaped even when the content is garbage: it is rejected on the JWT path.
func TestOpaque_TwoDotGarbageIsNotLookedUp(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{})
	useOpenfort(t, f)

	if _, err := VerifyOrDecode(context.Background(), "aaa.bbb.ccc"); err == nil {
		t.Fatal("garbage accepted")
	}
	if n := f.hits.Load(); n != 0 {
		t.Errorf("garbage with three segments triggered %d lookups", n)
	}
}

// ── Through the real interceptor ─────────────────────────────────────────────

func TestOpaque_InterceptorAdmitsAKnownToken_AndAttachesVerifiedClaims(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{opaqueToken: {"usr_real", "me@x.io"}})
	useOpenfort(t, f)
	t.Setenv("AUTH_REQUIRE_TOKEN", "")

	reached, claims, err := callInterceptor(t, "Bearer "+opaqueToken)
	if err != nil || !reached {
		t.Fatalf("reached=%v err=%v — a signed-in user's opaque token must pass", reached, err)
	}
	if claims == nil || claims.Subject != "usr_real" || !claims.Verified {
		t.Errorf("handler saw claims %+v", claims)
	}
}

func TestOpaque_InterceptorRefusesAnUnknownToken(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{})
	useOpenfort(t, f)

	reached, _, err := callInterceptor(t, "Bearer "+opaqueToken)
	if reached || connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("reached=%v code=%v — an unknown opaque token must be refused", reached, connect.CodeOf(err))
	}
}

// An email Openfort has not verified must not reach authorisation decisions (ADMIN_EMAILS, sponsor
// match): the caller is still who the token says, but carries no email.
func TestOpaque_UnverifiedEmailIsNotTrusted(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{opaqueToken: {"usr_abc123", "admin@everyflow.io"}})
	useOpenfort(t, f)
	t.Setenv("OPENFORT_TRUST_UNVERIFIED_EMAIL", "")
	f.unverified.Store(opaqueToken, true)

	c, err := VerifyOrDecode(context.Background(), opaqueToken)
	if err != nil {
		t.Fatalf("an unverified email must not make the token invalid: %v", err)
	}
	if c.Subject != "usr_abc123" || !c.Verified {
		t.Errorf("claims = %+v, want the subject kept and Verified=true", c)
	}
	if c.Email != "" {
		t.Errorf("email = %q, want it dropped because Openfort reports it unverified", c.Email)
	}
}

func TestOpaque_MissingVerifiedFlagCountsAsUnverified(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{opaqueToken: {"usr_abc123", "admin@everyflow.io"}})
	useOpenfort(t, f)
	t.Setenv("OPENFORT_TRUST_UNVERIFIED_EMAIL", "")
	f.omitFlag.Store(true)

	c, err := VerifyOrDecode(context.Background(), opaqueToken)
	if err != nil || c.Email != "" || c.Subject != "usr_abc123" {
		t.Errorf("claims = %+v err = %v, want subject kept and no email", c, err)
	}
}

func TestOpaque_TrustUnverifiedEmailSwitch(t *testing.T) {
	f := newFakeOpenfort(t, map[string][2]string{opaqueToken: {"usr_abc123", "admin@everyflow.io"}})
	useOpenfort(t, f)
	f.unverified.Store(opaqueToken, true)

	for _, v := range []string{"false", "yes", "1", ""} { // only an exact "true" opens it
		t.Setenv("OPENFORT_TRUST_UNVERIFIED_EMAIL", v)
		resetOpaqueCache()
		if c, _ := VerifyOrDecode(context.Background(), opaqueToken); c == nil || c.Email != "" {
			t.Errorf("OPENFORT_TRUST_UNVERIFIED_EMAIL=%q: email = %+v, want dropped", v, c)
		}
	}
	t.Setenv("OPENFORT_TRUST_UNVERIFIED_EMAIL", "true")
	resetOpaqueCache()
	if c, _ := VerifyOrDecode(context.Background(), opaqueToken); c == nil || c.Email != "admin@everyflow.io" {
		t.Errorf("with the switch on, email = %+v, want admin@everyflow.io", c)
	}
}
