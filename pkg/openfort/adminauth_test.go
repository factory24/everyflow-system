package openfort

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/factory24/everyflow-system/pkg/auth"
)

const testProcedure = "/test.v1.Admin/Mutate"

// unsignedJWT is what anyone can mint by hand: a JWT-shaped token with alg none
// and whatever email they like. With OPENFORT_JWKS_URL unset the shared auth
// package only DECODES, so it reads the email straight out of this.
func unsignedJWT(email string) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." +
		enc(map[string]any{"sub": "x", "email": email, "exp": 4102444800}) + "."
}

// fakeOpenfort answers GET /iam/v2/me for a fixed set of opaque tokens (token ->
// email) and GET /v2/users with two records; it counts how often each is hit.
type fakeOpenfort struct {
	*httptest.Server
	meCalls, usersCalls int
	unverified          map[string]bool // tokens whose email is reported as not verified
	omitFlag            bool            // answer without an emailVerified field
}

func newFakeOpenfort(t *testing.T, tokens map[string]string) *fakeOpenfort {
	t.Helper()
	f := &fakeOpenfort{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/iam/v2/me":
			f.meCalls++
			email, ok := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			body := map[string]any{"id": "usr_1", "email": email}
			if !f.omitFlag {
				body["emailVerified"] = !f.unverified[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
			}
			_ = json.NewEncoder(w).Encode(body)
		case "/v2/users":
			f.usersCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":  []map[string]any{{"id": "usr_1", "email": "a@x.io"}, {"id": "usr_2", "email": "b@x.io"}},
				"total": 2,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeOpenfort) cfg() UsersConfig {
	return UsersConfig{SecretKey: "sk_test", BaseURL: f.URL}
}

func adminOnly(t *testing.T) {
	t.Helper()
	t.Setenv("ADMIN_EMAILS", "admin@everyflow.io")
	t.Setenv("OPENFORT_JWKS_URL", "") // decode-only: the local-dev posture
	t.Setenv("AUTH_REQUIRE_TOKEN", "")
}

// gate mounts the REAL AdminGateInterceptor on a throwaway Connect handler and
// returns the status/code a caller with `token` gets.
func gate(t *testing.T, cfg UsersConfig, token string) (reached bool, code connect.Code, denied bool) {
	t.Helper()
	handler := connect.NewUnaryHandler(testProcedure,
		func(ctx context.Context, req *connect.Request[wrapperspb.StringValue]) (*connect.Response[wrapperspb.StringValue], error) {
			reached = true
			return connect.NewResponse(wrapperspb.String("ok")), nil
		},
		connect.WithInterceptors(AdminGateInterceptor(cfg, map[string]bool{testProcedure: true})),
	)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := connect.NewClient[wrapperspb.StringValue, wrapperspb.StringValue](srv.Client(), srv.URL+testProcedure)
	req := connect.NewRequest(wrapperspb.String("x"))
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	_, err := client.CallUnary(context.Background(), req)
	if err != nil {
		return reached, connect.CodeOf(err), true
	}
	return reached, 0, false
}

func TestAdminGate_ForgedUnsignedTokenIsNotTrusted(t *testing.T) {
	adminOnly(t)
	f := newFakeOpenfort(t, map[string]string{"opaque-admin": "admin@everyflow.io", "opaque-user": "user@x.io"})

	// The exploit: an unsigned JWT naming an allowlisted admin. Decode-only mode
	// would read that email and wave it through; it must go to Openfort, which
	// does not know the token, so the call is refused and the handler never runs.
	reached, code, denied := gate(t, f.cfg(), unsignedJWT("admin@everyflow.io"))
	if reached || !denied {
		t.Fatalf("forged admin token reached the handler (reached=%v denied=%v)", reached, denied)
	}
	if code != connect.CodeUnauthenticated {
		t.Errorf("code = %v, want unauthenticated", code)
	}
	if f.meCalls != 1 {
		t.Errorf("Openfort WhoAmI called %d times, want 1 (unverified token must be checked upstream)", f.meCalls)
	}
}

func TestAdminGate_Matrix(t *testing.T) {
	adminOnly(t)
	f := newFakeOpenfort(t, map[string]string{"opaque-admin": "admin@everyflow.io", "opaque-user": "user@x.io"})

	cases := []struct {
		name      string
		token     string
		wantReach bool
		wantCode  connect.Code
	}{
		{"no token", "", false, connect.CodeUnauthenticated},
		{"unknown opaque token", "garbage", false, connect.CodeUnauthenticated},
		{"real opaque token, non-admin", "opaque-user", false, connect.CodePermissionDenied},
		{"real opaque token, admin", "opaque-admin", true, 0},
		{"forged JWT, non-admin email", unsignedJWT("user@x.io"), false, connect.CodeUnauthenticated},
		{"forged JWT, admin email", unsignedJWT("admin@everyflow.io"), false, connect.CodeUnauthenticated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reached, code, denied := gate(t, f.cfg(), c.token)
			if reached != c.wantReach {
				t.Fatalf("reached handler = %v, want %v", reached, c.wantReach)
			}
			if c.wantReach == denied {
				t.Fatalf("denied = %v, want %v", denied, !c.wantReach)
			}
			if !c.wantReach && code != c.wantCode {
				t.Errorf("code = %v, want %v", code, c.wantCode)
			}
		})
	}
}

func TestUsersHandler_RequiresAdminIdentity(t *testing.T) {
	adminOnly(t) // AUTH_REQUIRE_TOKEN deliberately unset: must NOT make a missing token acceptable
	f := newFakeOpenfort(t, map[string]string{"opaque-admin": "admin@everyflow.io", "opaque-user": "user@x.io"})
	h := UsersHandler(f.cfg())

	get := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/admin/openfort-users", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w
	}

	for _, c := range []struct {
		name  string
		token string
		want  int
	}{
		{"no token (AUTH_REQUIRE_TOKEN unset)", "", http.StatusUnauthorized},
		{"forged JWT naming an admin", unsignedJWT("admin@everyflow.io"), http.StatusForbidden},
		{"real non-admin", "opaque-user", http.StatusForbidden},
		{"real admin", "opaque-admin", http.StatusOK},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := f.usersCalls
			w := get(c.token)
			if w.Code != c.want {
				t.Fatalf("status = %d, want %d", w.Code, c.want)
			}
			leaked := f.usersCalls != before
			if c.want != http.StatusOK && leaked {
				t.Errorf("user list was fetched from Openfort for a refused caller")
			}
			if c.want == http.StatusOK && !strings.Contains(w.Body.String(), fmt.Sprintf(`"total":%d`, 2)) {
				t.Errorf("admin got unexpected body: %s", w.Body.String())
			}
		})
	}
}

func TestAdminGateMiddleware(t *testing.T) {
	adminOnly(t)
	f := newFakeOpenfort(t, map[string]string{"opaque-admin": "admin@everyflow.io", "opaque-user": "user@x.io"})

	for _, c := range []struct {
		name      string
		method    string
		token     string
		wantCode  int
		wantReach bool
	}{
		{"no token", http.MethodPost, "", http.StatusUnauthorized, false},
		{"unknown opaque token", http.MethodPost, "garbage", http.StatusUnauthorized, false},
		{"forged JWT naming an admin", http.MethodPost, unsignedJWT("admin@everyflow.io"), http.StatusUnauthorized, false},
		{"real non-admin", http.MethodPost, "opaque-user", http.StatusForbidden, false},
		{"real admin", http.MethodPost, "opaque-admin", http.StatusOK, true},
		{"preflight needs no credentials", http.MethodOptions, "", http.StatusOK, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			reached := false
			h := AdminGateMiddleware(f.cfg(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
			}))
			r := httptest.NewRequest(c.method, "/x", nil)
			if c.token != "" {
				r.Header.Set("Authorization", "Bearer "+c.token)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.wantCode || reached != c.wantReach {
				t.Fatalf("status=%d reached=%v, want status=%d reached=%v", w.Code, reached, c.wantCode, c.wantReach)
			}
		})
	}
}

// An Openfort outage while checking an admin must not read as "you are not signed in": the gate answers
// Unavailable (503 on the HTTP middleware), a token Openfort refuses stays Unauthenticated (401).
func TestAdminGate_OpenfortOutageIsUnavailableNotUnauthenticated(t *testing.T) {
	adminOnly(t)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer down.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close() // nothing listening

	for name, base := range map[string]string{"openfort 502": down.URL, "openfort unreachable": goneURL} {
		cfg := UsersConfig{SecretKey: "sk_test", BaseURL: base}
		reached, code, denied := gate(t, cfg, "some-opaque-token")
		if !denied || code != connect.CodeUnavailable || reached {
			t.Errorf("%s: interceptor code=%v denied=%v reached=%v, want Unavailable", name, code, denied, reached)
		}
		h := AdminGateMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("handler ran during an outage") }))
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		r.Header.Set("Authorization", "Bearer some-opaque-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: middleware status %d, want 503", name, w.Code)
		}
	}

	// Openfort answering "no" is still a 401 / Unauthenticated, not an outage.
	f := newFakeOpenfort(t, map[string]string{"opaque-admin": "admin@everyflow.io"})
	if _, code, denied := gate(t, f.cfg(), "garbage"); !denied || code != connect.CodeUnauthenticated {
		t.Errorf("a refused token: code=%v denied=%v, want Unauthenticated", code, denied)
	}
	// ...and a healthy Openfort still lets the admin through.
	if reached, _, denied := gate(t, f.cfg(), "opaque-admin"); denied || !reached {
		t.Errorf("a real admin was refused (reached=%v denied=%v)", reached, denied)
	}
}

func TestWhoAmI_ClassifiesOutagesButNotRefusals(t *testing.T) {
	for _, c := range []struct {
		status      int
		unavailable bool
	}{{500, true}, {502, true}, {503, true}, {429, true}, {401, false}, {403, false}, {404, false}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", c.status) }))
		_, err := UsersConfig{BaseURL: srv.URL}.WhoAmI(context.Background(), "tok")
		srv.Close()
		if err == nil || auth.IsUnavailable(err) != c.unavailable {
			t.Errorf("status %d: err=%v, IsUnavailable=%v, want %v", c.status, err, auth.IsUnavailable(err), c.unavailable)
		}
	}
}

// A token whose email is the allowlisted admin address but which Openfort reports as UNVERIFIED must not
// pass the admin gate, whether the flag is false or missing.
func TestAdminGate_UnverifiedAdminEmailIsRefused(t *testing.T) {
	adminOnly(t)
	t.Setenv("OPENFORT_TRUST_UNVERIFIED_EMAIL", "")
	f := newFakeOpenfort(t, map[string]string{"opaque-admin": "admin@everyflow.io"})

	if reached, _, denied := gate(t, f.cfg(), "opaque-admin"); !reached || denied {
		t.Fatalf("control: a verified admin must pass (reached=%v denied=%v)", reached, denied)
	}

	f.unverified = map[string]bool{"opaque-admin": true}
	if reached, code, denied := gate(t, f.cfg(), "opaque-admin"); reached || !denied || code != connect.CodeUnauthenticated {
		t.Errorf("unverified email: reached=%v denied=%v code=%v, want refused as unauthenticated", reached, denied, code)
	}

	f.unverified, f.omitFlag = nil, true
	if reached, _, denied := gate(t, f.cfg(), "opaque-admin"); reached || !denied {
		t.Errorf("missing flag: reached=%v denied=%v, want refused", reached, denied)
	}

	t.Setenv("OPENFORT_TRUST_UNVERIFIED_EMAIL", "true")
	if reached, _, denied := gate(t, f.cfg(), "opaque-admin"); !reached || denied {
		t.Errorf("escape hatch on: reached=%v denied=%v, want admitted", reached, denied)
	}
}
