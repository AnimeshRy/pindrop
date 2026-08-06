// Package auth verifies Supabase access tokens for cloud deployments.
package auth

// Claims holds the identity fields we trust after JWT verification.
type Claims struct {
	Subject string
	Email   string
	Name    string
}
