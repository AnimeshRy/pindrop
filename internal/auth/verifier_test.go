package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/AnimeshRy/pindrop/internal/auth"
)

type testKey struct {
	private *ecdsa.PrivateKey
	kid     string
}

func newTestKey(t *testing.T) testKey {
	t.Helper()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return testKey{private: private, kid: "test-kid"}
}

func (k testKey) jwksJSON(t *testing.T) []byte {
	t.Helper()

	size := (k.private.Curve.Params().BitSize + 7) / 8
	// Test-only JWKS encoding; production paths parse JWK coordinates in jwks.go.
	xBytes := k.private.PublicKey.X.FillBytes(make([]byte, size)) //nolint:staticcheck
	yBytes := k.private.PublicKey.Y.FillBytes(make([]byte, size)) //nolint:staticcheck
	x := base64.RawURLEncoding.EncodeToString(xBytes)
	y := base64.RawURLEncoding.EncodeToString(yBytes)
	doc := map[string]any{
		"keys": []map[string]string{
			{
				"kty": "EC",
				"crv": "P-256",
				"kid": k.kid,
				"alg": "ES256",
				"x":   x,
				"y":   y,
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return raw
}

func (k testKey) mint(t *testing.T, issuer string, mutate func(jwt.MapClaims)) string {
	t.Helper()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   "user-123",
		"aud":   "authenticated",
		"email": "someone@example.com",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"user_metadata": map[string]any{
			"full_name": "Ada Lovelace",
		},
	}
	if mutate != nil {
		mutate(claims)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = k.kid
	signed, err := token.SignedString(k.private)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return signed
}

func newTestVerifier(t *testing.T, key testKey) (*auth.Verifier, string) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(key.jwksJSON(t))
	}))
	t.Cleanup(srv.Close)

	// Point Verifier at the test server by rewriting the Supabase URL base.
	verifier, err := auth.NewVerifier(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return verifier, srv.URL + "/auth/v1"
}

func TestVerifyValidToken(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	verifier, issuer := newTestVerifier(t, key)
	token := key.mint(t, issuer, nil)

	got, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if got.Subject != "user-123" {
		t.Errorf("Subject = %q, want user-123", got.Subject)
	}
	if got.Email != "someone@example.com" {
		t.Errorf("Email = %q, want someone@example.com", got.Email)
	}
	if got.Name != "Ada Lovelace" {
		t.Errorf("Name = %q, want Ada Lovelace", got.Name)
	}
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	verifier, issuer := newTestVerifier(t, key)

	tests := []struct {
		name   string
		token  string
		mutate func(jwt.MapClaims)
	}{
		{"empty", "", nil},
		{"wrong issuer", key.mint(t, issuer+"/wrong", nil), nil},
		{"expired", key.mint(t, issuer, func(c jwt.MapClaims) {
			c["exp"] = time.Now().Add(-time.Hour).Unix()
		}), nil},
		{"wrong audience", key.mint(t, issuer, func(c jwt.MapClaims) {
			c["aud"] = "anon"
		}), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := tt.token
			if token == "" && tt.mutate == nil {
				token = ""
			}
			if _, err := verifier.Verify(context.Background(), token); err == nil {
				t.Fatal("Verify() error = nil, want an error")
			}
		})
	}
}

func TestVerifyRejectsHS256(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	verifier, issuer := newTestVerifier(t, key)

	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": "user-123",
		"aud": "authenticated",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = key.kid
	signed, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	if _, err := verifier.Verify(context.Background(), signed); err == nil {
		t.Fatal("Verify() error = nil, want rejection of HS256")
	}
}
