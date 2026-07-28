package openfort

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testCfg(baseURL string) ShieldConfig {
	return ShieldConfig{
		ShieldAPIKey:    "shield-pub",
		ShieldSecretKey: "shield-secret",
		EncryptionShare: "share-xyz",
		ShieldBaseURL:   baseURL,
	}
}

func TestCreateEncryptionSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/project/encryption-session" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "shield-pub" || r.Header.Get("x-api-secret") != "shield-secret" {
			t.Errorf("missing shield auth headers")
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["encryption_part"] != "share-xyz" {
			t.Errorf("bad encryption_part: %q", body["encryption_part"])
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"session_id": "sess-123"})
	}))
	defer srv.Close()

	id, err := testCfg(srv.URL).CreateEncryptionSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != "sess-123" {
		t.Fatalf("want sess-123, got %q", id)
	}
}

func TestCreateEncryptionSession_NotConfigured(t *testing.T) {
	if _, err := (ShieldConfig{}).CreateEncryptionSession(context.Background()); err == nil {
		t.Fatal("expected error when shield env not set")
	}
}

func TestEncryptionSessionHandler(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"session_id": "sess-abc"})
	}))
	defer upstream.Close()

	h := EncryptionSessionHandler(testCfg(upstream.URL))

	// Preflight
	pre := httptest.NewRecorder()
	h(pre, httptest.NewRequest(http.MethodOptions, "/api/protected-create-encryption-session", nil))
	if pre.Code != http.StatusNoContent || pre.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatalf("preflight: code=%d cors=%q", pre.Code, pre.Header().Get("Access-Control-Allow-Origin"))
	}

	// POST
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/protected-create-encryption-session", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("post code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"session":"sess-abc"`) {
		t.Fatalf("bad body: %s", rec.Body.String())
	}
}
