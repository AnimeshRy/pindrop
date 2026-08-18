// Package api exposes the product HTTP API (versioned under /api/v1).
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/AnimeshRy/pindrop/server/internal/authmw"
)

// Config wires the API handlers.
type Config struct {
	Auth *authmw.Middleware
}

// Server registers product API routes on an [http.ServeMux].
type Server struct {
	mux *http.ServeMux
}

// New returns a Server with the standard /api/v1 routes registered.
func New(cfg Config) *Server {
	s := &Server{mux: http.NewServeMux()}
	s.routes(cfg)
	return s
}

// Handler returns the root handler, including CORS, for the API server.
func (s *Server) Handler(corsOrigin string) http.Handler {
	return cors(corsOrigin, s.mux)
}

func (s *Server) routes(cfg Config) {
	s.mux.HandleFunc("GET /api/v1/healthz", handleHealth)
	if cfg.Auth != nil {
		s.mux.Handle("GET /api/v1/me", cfg.Auth.Require(http.HandlerFunc(handleMe)))
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"tool":   "pindrop-server",
	})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := authmw.UserFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"id":    user.ID,
		"email": user.Email,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// cors allows browser clients on a different origin to call the API with JWTs.
func cors(origin string, next http.Handler) http.Handler {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		origin = "*"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
