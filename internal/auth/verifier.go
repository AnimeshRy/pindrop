package auth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Verifier validates Supabase access tokens using the project's JWKS endpoint.
type Verifier struct {
	issuer   string
	jwksURL  string
	client   *http.Client
	keyCache *keyCache
}

// NewVerifier constructs a Verifier for a Supabase project URL such as
// https://example.supabase.co (no trailing slash).
func NewVerifier(supabaseURL string, client *http.Client) (*Verifier, error) {
	base := strings.TrimRight(strings.TrimSpace(supabaseURL), "/")
	if base == "" {
		return nil, errors.New("auth: supabase URL is required")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &Verifier{
		issuer:   base + "/auth/v1",
		jwksURL:  base + "/auth/v1/.well-known/jwks.json",
		client:   client,
		keyCache: newKeyCache(),
	}, nil
}

// Verify parses and validates token, returning trusted identity claims.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Claims{}, errors.New("missing access token")
	}

	parsed, err := jwt.Parse(token, v.keyFunc(ctx), jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		return Claims{}, fmt.Errorf("invalid access token: %w", err)
	}
	if !parsed.Valid {
		return Claims{}, errors.New("invalid access token")
	}

	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return Claims{}, errors.New("invalid access token claims")
	}

	if err := v.validateStandardClaims(mapClaims); err != nil {
		return Claims{}, err
	}

	return Claims{
		Subject: stringClaim(mapClaims, "sub"),
		Email:   stringClaim(mapClaims, "email"),
		Name:    nameFromClaims(mapClaims),
	}, nil
}

func (v *Verifier) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		if t.Method == nil || t.Method.Alg() != jwt.SigningMethodES256.Alg() {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}

		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token missing kid header")
		}

		pub, err := v.lookupKey(ctx, kid)
		if err != nil {
			return nil, err
		}
		return pub, nil
	}
}

func (v *Verifier) lookupKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	if pub, ok := v.keyCache.get(kid); ok {
		return pub, nil
	}

	if v.keyCache.needsRefresh() || v.keyCache.allowRefresh() {
		keys, err := fetchJWKS(ctx, v.client, v.jwksURL)
		if err != nil {
			return nil, err
		}
		v.keyCache.replace(keys)
		if pub, ok := keys[kid]; ok {
			return pub, nil
		}
	}

	if pub, ok := v.keyCache.get(kid); ok {
		return pub, nil
	}
	return nil, errors.New("no matching signing key for token")
}

func (v *Verifier) validateStandardClaims(mapClaims jwt.MapClaims) error {
	issuer, err := mapClaims.GetIssuer()
	if err != nil || issuer != v.issuer {
		return errors.New("invalid token issuer")
	}

	exp, err := mapClaims.GetExpirationTime()
	if err != nil || exp == nil || time.Now().After(exp.Time) {
		return errors.New("access token expired")
	}

	if nbf, err := mapClaims.GetNotBefore(); err == nil && nbf != nil && time.Now().Before(nbf.Time) {
		return errors.New("access token not yet valid")
	}

	if !audienceContainsAuthenticated(mapClaims["aud"]) {
		return errors.New("invalid token audience")
	}

	if stringClaim(mapClaims, "sub") == "" {
		return errors.New("token missing subject")
	}

	return nil
}

func audienceContainsAuthenticated(aud any) bool {
	switch v := aud.(type) {
	case string:
		return v == "authenticated"
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == "authenticated" {
				return true
			}
		}
	}
	return false
}

func stringClaim(claims jwt.MapClaims, key string) string {
	raw, ok := claims[key]
	if !ok || raw == nil {
		return ""
	}
	s, _ := raw.(string)
	return s
}

func nameFromClaims(claims jwt.MapClaims) string {
	if meta, ok := claims["user_metadata"].(map[string]any); ok {
		if name := stringFromAny(meta["full_name"]); name != "" {
			return name
		}
		if name := stringFromAny(meta["name"]); name != "" {
			return name
		}
	}
	if email := stringClaim(claims, "email"); email != "" {
		return email
	}
	return stringClaim(claims, "sub")
}

func stringFromAny(v any) string {
	s, _ := v.(string)
	return s
}
