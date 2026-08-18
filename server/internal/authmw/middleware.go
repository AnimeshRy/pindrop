// Package authmw verifies Supabase-issued JWT access tokens using the project's
// JWKS endpoint and attaches the authenticated user to request context.
package authmw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// User holds the identity extracted from a verified Supabase access token.
type User struct {
	ID    string
	Email string
}

type userContextKey struct{}

// UserFromContext returns the authenticated user, if any.
func UserFromContext(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(userContextKey{}).(User)
	return user, ok
}

// Config configures JWT verification against a Supabase project.
type Config struct {
	// ProjectURL is the Supabase project URL, e.g. https://abc.supabase.co
	ProjectURL string
}

// Middleware validates Bearer tokens and injects [User] into the context.
type Middleware struct {
	jwks   keyfunc.Keyfunc
	issuer string
}

// New builds middleware that verifies RS256 tokens from the given Supabase project.
func New(cfg Config) (*Middleware, error) {
	projectURL := strings.TrimRight(strings.TrimSpace(cfg.ProjectURL), "/")
	if projectURL == "" {
		return nil, errors.New("authmw: ProjectURL is required")
	}

	jwksURL := projectURL + "/auth/v1/.well-known/jwks.json"
	jwks, err := keyfunc.NewDefault([]string{jwksURL})
	if err != nil {
		return nil, fmt.Errorf("authmw: loading JWKS from %s: %w", jwksURL, err)
	}

	return &Middleware{
		jwks:   jwks,
		issuer: projectURL + "/auth/v1",
	}, nil
}

// Require wraps a handler and rejects requests without a valid Supabase JWT.
func (m *Middleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := bearerToken(r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}

		user, err := m.verify(tokenString)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) verify(tokenString string) (User, error) {
	token, err := jwt.Parse(tokenString, m.jwks.Keyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return User{}, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		return User{}, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return User{}, errors.New("invalid token claims")
	}

	if err := jwt.NewValidator(
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience("authenticated"),
	).Validate(claims); err != nil {
		return User{}, fmt.Errorf("invalid token claims: %w", err)
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return User{}, errors.New("token missing sub claim")
	}

	email, _ := claims["email"].(string)

	return User{ID: sub, Email: email}, nil
}

func bearerToken(header string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", errors.New("missing authorization header")
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return "", errors.New("missing bearer token")
	}
	return token, nil
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
