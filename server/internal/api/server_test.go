package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AnimeshRy/pindrop/server/internal/api"
)

func TestHealthz(t *testing.T) {
	t.Parallel()

	srv := api.New(api.Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler("*").ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
