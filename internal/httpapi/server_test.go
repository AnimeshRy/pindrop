package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/AnimeshRy/pindrop/internal/httpapi"
	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// stubSource serves a fixed document, or a fixed error.
type stubSource struct {
	doc report.Document
	err error
}

func (s stubSource) Document() (report.Document, error) {
	return s.doc, s.err
}

func testDocument() report.Document {
	return report.Document{
		SchemaVersion: report.DocumentSchemaVersion,
		Findings: []scan.Finding{
			{
				Fingerprint: "a1", RuleID: "CVE-1", Scanner: "trivy",
				Category: scan.CategoryVulnerability, Severity: scan.SeverityCritical,
				Location: scan.Location{Path: "package-lock.json"},
			},
			{
				Fingerprint: "b2", RuleID: "SECRET-1", Scanner: "trivy",
				Category: scan.CategorySecret, Severity: scan.SeverityHigh,
				Location: scan.Location{Path: ".env", StartLine: 3},
			},
			{
				Fingerprint: "c3", RuleID: "AVD-1", Scanner: "trivy",
				Category: scan.CategoryMisconfiguration, Severity: scan.SeverityLow,
				Location: scan.Location{Path: "Dockerfile", StartLine: 1},
			},
		},
	}
}

// testAssets is a stand-in for the built SPA.
func testAssets() fstest.MapFS {
	return fstest.MapFS{
		"index.html":            {Data: []byte("<!doctype html><title>Pindrop</title>")},
		"assets/main-abc123.js": {Data: []byte("console.log('hi')")},
	}
}

func newTestServer(t *testing.T, cfg httpapi.Config) *httpapi.Server {
	t.Helper()

	srv, err := httpapi.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	return srv
}

func get(t *testing.T, srv *httpapi.Server, target string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

type stubVerifier struct {
	user httpapi.UserIdentity
	err  error
}

func (s stubVerifier) Verify(_ context.Context, token string) (httpapi.UserIdentity, error) {
	if s.err != nil {
		return httpapi.UserIdentity{}, s.err
	}
	if token != "good-token" {
		return httpapi.UserIdentity{}, errors.New("bad token")
	}
	if s.user.Subject != "" {
		return s.user, nil
	}
	return httpapi.UserIdentity{Subject: "user-1", Email: "a@b.com", Name: "Ada"}, nil
}

func TestConfigSelfHosted(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{Source: stubSource{doc: testDocument()}})
	rec := get(t, srv, "/api/v1/config")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body["mode"] != "self-hosted" {
		t.Errorf("mode = %v, want self-hosted", body["mode"])
	}
	if _, ok := body["supabaseUrl"]; ok {
		t.Error("self-hosted config must not expose supabaseUrl")
	}
}

func TestConfigCloud(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{
		Source:         stubSource{doc: testDocument()},
		Mode:           httpapi.ModeCloud,
		SupabaseURL:    "https://example.supabase.co",
		PublishableKey: "sb_publishable_test",
	})
	rec := get(t, srv, "/api/v1/config")

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body["mode"] != "cloud" {
		t.Errorf("mode = %q, want cloud", body["mode"])
	}
	if body["supabaseUrl"] != "https://example.supabase.co" {
		t.Errorf("supabaseUrl = %q, want example URL", body["supabaseUrl"])
	}
}

func TestFindingsRequiresAuthInCloudMode(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{
		Source:   stubSource{doc: testDocument()},
		Mode:     httpapi.ModeCloud,
		Verifier: stubVerifier{},
	})

	rec := get(t, srv, "/api/v1/findings")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMe(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{
		Source:   stubSource{doc: testDocument()},
		Verifier: stubVerifier{user: httpapi.UserIdentity{Subject: "u1", Name: "Ada"}},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body httpapi.UserIdentity
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body.Name != "Ada" {
		t.Errorf("Name = %q, want Ada", body.Name)
	}
}

func TestNewRequiresSource(t *testing.T) {
	t.Parallel()

	if _, err := httpapi.New(httpapi.Config{}); err == nil {
		t.Fatal("New() with no Source error = nil, want an error")
	}
}

func TestHealthz(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{Source: stubSource{doc: testDocument()}})
	rec := get(t, srv, "/api/v1/healthz")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
}

func TestFindings(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{Source: stubSource{doc: testDocument()}})

	tests := []struct {
		name  string
		query string
		want  int
	}{
		{"all", "/api/v1/findings", 3},
		{"one severity", "/api/v1/findings?severity=critical", 1},
		{"several severities", "/api/v1/findings?severity=critical,high", 2},
		{"severity case-insensitive", "/api/v1/findings?severity=CRITICAL", 1},
		{"by category", "/api/v1/findings?category=secret", 1},
		{"no match", "/api/v1/findings?severity=info", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := get(t, srv, tt.query)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}

			var body struct {
				Findings []scan.Finding `json:"findings"`
				Total    int            `json:"total"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if body.Total != tt.want {
				t.Errorf("total = %d, want %d", body.Total, tt.want)
			}
			if len(body.Findings) != tt.want {
				t.Errorf("len(findings) = %d, want %d", len(body.Findings), tt.want)
			}
		})
	}
}

func TestFindingsSourceFailure(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{
		Source: stubSource{err: errors.New("no scan report at .pindrop/report.json")},
	})

	rec := get(t, srv, "/api/v1/findings")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if body["error"] == "" {
		t.Error("response has no error message")
	}
}

func TestSummary(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{Source: stubSource{doc: testDocument()}})
	rec := get(t, srv, "/api/v1/summary")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Total      int            `json:"total"`
		BySeverity map[string]int `json:"bySeverity"`
		ByCategory map[string]int `json:"byCategory"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if body.Total != 3 {
		t.Errorf("total = %d, want 3", body.Total)
	}
	if body.BySeverity["critical"] != 1 {
		t.Errorf("bySeverity[critical] = %d, want 1", body.BySeverity["critical"])
	}
	if body.ByCategory["secret"] != 1 {
		t.Errorf("byCategory[secret] = %d, want 1", body.ByCategory["secret"])
	}
}

func TestSPAServesAssets(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{
		Assets: testAssets(),
		Source: stubSource{doc: testDocument()},
	})

	rec := get(t, srv, "/assets/main-abc123.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	// Hashed bundles must be cached aggressively or every page load refetches.
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Error("hashed asset has no Cache-Control header")
	}
}

// TestSPAFallback is what makes client-side routing work: a deep link must
// return the app shell so the router can resolve it, not a 404.
func TestSPAFallback(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{
		Assets: testAssets(),
		Source: stubSource{doc: testDocument()},
	})

	for _, target := range []string{"/", "/findings", "/settings/deep/link"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rec := get(t, srv, target)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if got := rec.Body.String(); got != "<!doctype html><title>Pindrop</title>" {
				t.Errorf("body = %q, want the SPA shell", got)
			}
			// The shell must never be cached, or users get a stale document
			// referencing bundles that no longer exist.
			if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
				t.Errorf("Cache-Control = %q, want %q", cc, "no-cache")
			}
		})
	}
}

// TestAPIRoutesWinOverSPA guards against the catch-all swallowing the API.
func TestAPIRoutesWinOverSPA(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{
		Assets: testAssets(),
		Source: stubSource{doc: testDocument()},
	})

	rec := get(t, srv, "/api/v1/healthz")
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want JSON — the SPA handler captured an API route", ct)
	}
}

// TestSPAWithoutAssets covers a binary built before the frontend: the API must
// still work and the page must explain itself.
func TestSPAWithoutAssets(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, httpapi.Config{Source: stubSource{doc: testDocument()}})

	rec := get(t, srv, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); !strings.Contains(body, "make web") {
		t.Errorf("placeholder page does not say how to build the UI:\n%s", body)
	}

	if rec := get(t, srv, "/api/v1/findings"); rec.Code != http.StatusOK {
		t.Errorf("API status = %d with no assets, want %d", rec.Code, http.StatusOK)
	}
}
