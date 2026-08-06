package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultCacheTTL   = 10 * time.Minute
	refreshMinSpacing = 5 * time.Second
)

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type keyCache struct {
	mu          sync.RWMutex
	keys        map[string]*ecdsa.PublicKey
	fetchedAt   time.Time
	lastRefresh time.Time
}

func newKeyCache() *keyCache {
	return &keyCache{keys: make(map[string]*ecdsa.PublicKey)}
}

func (c *keyCache) get(kid string) (*ecdsa.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	return key, ok
}

func (c *keyCache) replace(keys map[string]*ecdsa.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = keys
	c.fetchedAt = time.Now()
}

func (c *keyCache) needsRefresh() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.fetchedAt) > defaultCacheTTL
}

func (c *keyCache) allowRefresh() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if now.Sub(c.lastRefresh) < refreshMinSpacing {
		return false
	}
	c.lastRefresh = now
	return true
}

func fetchJWKS(ctx context.Context, client *http.Client, jwksURL string) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building jwks request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching jwks: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching jwks: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading jwks: %w", err)
	}

	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decoding jwks: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, raw := range doc.Keys {
		if raw.Alg != "" && raw.Alg != "ES256" {
			continue
		}
		pub, err := jwkToECDSA(raw)
		if err != nil {
			return nil, err
		}
		if raw.Kid == "" {
			return nil, errors.New("jwks key missing kid")
		}
		keys[raw.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks has no usable ES256 keys")
	}
	return keys, nil
}

func jwkToECDSA(raw jwk) (*ecdsa.PublicKey, error) {
	if raw.Kty != "EC" {
		return nil, fmt.Errorf("unsupported jwk kty %q", raw.Kty)
	}
	curve, err := curveForCRV(raw.Crv)
	if err != nil {
		return nil, err
	}

	x, err := decodeCoordinate(raw.X)
	if err != nil {
		return nil, fmt.Errorf("decoding jwk x: %w", err)
	}
	y, err := decodeCoordinate(raw.Y)
	if err != nil {
		return nil, fmt.Errorf("decoding jwk y: %w", err)
	}

	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	return pub, nil
}

func curveForCRV(crv string) (elliptic.Curve, error) {
	switch strings.ToUpper(crv) {
	case "P-256":
		return elliptic.P256(), nil
	default:
		return nil, fmt.Errorf("unsupported jwk crv %q", crv)
	}
}

func decodeCoordinate(s string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}
