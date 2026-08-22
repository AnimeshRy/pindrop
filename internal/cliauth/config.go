// Package cliauth obtains and refreshes Supabase sessions for the CLI.
//
// Login uses browser OAuth with a localhost callback and PKCE against GoTrue
// directly — the same Supabase project the web app uses, with no client secret.
package cliauth

import (
	"fmt"
	"os"
	"strings"
)

// Environment variable names override link-time defaults for local development.
const (
	envSupabaseURL     = "PINDROP_SUPABASE_URL"
	envSupabaseAnonKey = "PINDROP_SUPABASE_ANON_KEY"
	envAPIBaseURL      = "PINDROP_API_URL"
)

// Link-time defaults; release builds set these via -ldflags -X.
var (
	supabaseURL     string
	supabaseAnonKey string
	apiBaseURL      string
)

// Config holds the Supabase project and product API endpoints the CLI talks to.
type Config struct {
	SupabaseURL     string
	SupabaseAnonKey string
	APIBaseURL      string
}

// LoadConfig resolves settings from the environment, then link-time defaults.
func LoadConfig() (Config, error) {
	cfg := Config{
		SupabaseURL:     firstNonEmpty(os.Getenv(envSupabaseURL), supabaseURL),
		SupabaseAnonKey: firstNonEmpty(os.Getenv(envSupabaseAnonKey), supabaseAnonKey),
		APIBaseURL:      firstNonEmpty(os.Getenv(envAPIBaseURL), apiBaseURL),
	}

	cfg.SupabaseURL = normalizeSupabaseURL(cfg.SupabaseURL)
	cfg.APIBaseURL = strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")

	if cfg.SupabaseURL == "" {
		return Config{}, fmt.Errorf(
			"Supabase project URL is not configured — set %s or rebuild with release constants",
			envSupabaseURL)
	}
	if cfg.SupabaseAnonKey == "" {
		return Config{}, fmt.Errorf(
			"Supabase anon key is not configured — set %s or rebuild with release constants",
			envSupabaseAnonKey)
	}
	if cfg.APIBaseURL == "" {
		return Config{}, fmt.Errorf(
			"product API URL is not configured — set %s or rebuild with release constants",
			envAPIBaseURL)
	}
	return cfg, nil
}

// normalizeSupabaseURL strips accidental REST paths from the project URL.
func normalizeSupabaseURL(url string) string {
	url = strings.TrimSpace(url)
	url = strings.TrimSuffix(url, "/")
	const suffix = "/rest/v1"
	if strings.HasSuffix(strings.ToLower(url), suffix) {
		url = url[:len(url)-len(suffix)]
	}
	return strings.TrimSuffix(url, "/")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
