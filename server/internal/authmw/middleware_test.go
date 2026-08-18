package authmw_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AnimeshRy/pindrop/server/internal/authmw"
	"github.com/golang-jwt/jwt/v5"
)

func TestRequire_rejectsMissingToken(t *testing.T) {
	t.Parallel()

	mw := testMiddleware(t)
	next := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequire_acceptsValidToken(t *testing.T) {
	t.Parallel()

	mw, privateKey, projectURL := testMiddlewareWithKey(t)
	token := signToken(t, privateKey, projectURL+"/auth/v1", map[string]any{
		"sub":   "user-123",
		"email": "dev@example.com",
		"aud":   "authenticated",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	var got authmw.User
	next := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := authmw.UserFromContext(r.Context())
		if !ok {
			t.Fatal("expected user in context")
		}
		got = user
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if got.ID != "user-123" || got.Email != "dev@example.com" {
		t.Fatalf("user = %+v, want id=user-123 email=dev@example.com", got)
	}
}

func testMiddleware(t *testing.T) *authmw.Middleware {
	t.Helper()
	mw, _, _ := testMiddlewareWithKey(t)
	return mw
}

func testMiddlewareWithKey(t *testing.T) (*authmw.Middleware, *rsa.PrivateKey, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/v1/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}

		pub := privateKey.PublicKey
		payload := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "test-key",
					"use": "sig",
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(jwksServer.Close)

	projectURL := jwksServer.URL
	mw, err := authmw.New(authmw.Config{ProjectURL: projectURL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return mw, privateKey, projectURL
}

func signToken(t *testing.T, privateKey *rsa.PrivateKey, issuer string, claims map[string]any) string {
	t.Helper()

	claims["iss"] = issuer
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = "test-key"

	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}
