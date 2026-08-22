// Package orgmw attaches the caller's organization to request context after
// authmw has verified the Supabase JWT.
package orgmw

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/AnimeshRy/pindrop/server/internal/authmw"
	"github.com/AnimeshRy/pindrop/server/internal/syncstore"
)

type orgContextKey struct{}

// OrgFromContext returns the authenticated user's org, if any.
func OrgFromContext(ctx context.Context) (syncstore.Org, bool) {
	org, ok := ctx.Value(orgContextKey{}).(syncstore.Org)
	return org, ok
}

// Middleware lazily provisions a personal org and injects it into context.
type Middleware struct {
	store syncstore.Store
}

// New returns org middleware backed by store.
func New(store syncstore.Store) *Middleware {
	return &Middleware{store: store}
}

// Require wraps a handler and ensures the user has an org in context.
func (m *Middleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := authmw.UserFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}

		org, err := m.store.EnsurePersonalOrg(r.Context(), user.ID, user.Email)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not provision organization")
			return
		}

		ctx := context.WithValue(r.Context(), orgContextKey{}, org)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
