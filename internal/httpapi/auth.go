package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Mode describes whether the dashboard runs without auth or behind Supabase.
type Mode string

const (
	// ModeSelfHosted serves the local scan dashboard with no sign-in.
	ModeSelfHosted Mode = "self-hosted"
	// ModeCloud requires a valid Supabase access token on protected API routes.
	ModeCloud Mode = "cloud"
)

// TokenVerifier validates bearer access tokens issued by Supabase Auth.
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (UserIdentity, error)
}

// UserIdentity is the authenticated caller, as verified by the server.
type UserIdentity struct {
	Subject string `json:"subject"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

type contextKey int

const userContextKey contextKey = 1

// UserFromContext returns the verified identity attached by [requireAuth].
func UserFromContext(ctx context.Context) (UserIdentity, bool) {
	user, ok := ctx.Value(userContextKey).(UserIdentity)
	return user, ok
}

func withUser(ctx context.Context, user UserIdentity) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

// requireAuth wraps h when a verifier is configured. Public routes omit the
// wrapper entirely.
func requireAuth(verifier TokenVerifier, h http.HandlerFunc) http.HandlerFunc {
	if verifier == nil {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized,
				errors.New("sign in to view scan results — open the dashboard and use Google or GitHub"))
			return
		}

		user, err := verifier.Verify(r.Context(), token)
		if err != nil {
			writeError(w, http.StatusUnauthorized,
				errors.New("your session expired — sign in again from the dashboard"))
			return
		}

		h(w, r.WithContext(withUser(r.Context(), user)))
	}
}
