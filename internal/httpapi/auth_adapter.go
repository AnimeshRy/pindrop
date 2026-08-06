package httpapi

import (
	"context"

	"github.com/AnimeshRy/pindrop/internal/auth"
)

// AuthAdapter wraps [auth.Verifier] for the HTTP layer.
type AuthAdapter struct {
	inner *auth.Verifier
}

// NewAuthAdapter returns a TokenVerifier backed by Supabase JWKS verification.
func NewAuthAdapter(verifier *auth.Verifier) *AuthAdapter {
	return &AuthAdapter{inner: verifier}
}

// Verify implements [TokenVerifier].
func (a *AuthAdapter) Verify(ctx context.Context, token string) (UserIdentity, error) {
	claims, err := a.inner.Verify(ctx, token)
	if err != nil {
		return UserIdentity{}, err
	}
	return UserIdentity{
		Subject: claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
	}, nil
}
