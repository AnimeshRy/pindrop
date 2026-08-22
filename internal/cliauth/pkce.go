package cliauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// pkcePair holds a PKCE code verifier and its S256 challenge.
type pkcePair struct {
	Verifier  string
	Challenge string
}

// newPKCEPair generates a RFC 7636 code verifier and base64url-encoded SHA-256 challenge.
func newPKCEPair() (pkcePair, error) {
	// 32 random bytes → 43 base64url chars, within the 43–128 char requirement.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return pkcePair{}, fmt.Errorf("generating PKCE verifier: %w", err)
	}

	verifier := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	return pkcePair{Verifier: verifier, Challenge: challenge}, nil
}
