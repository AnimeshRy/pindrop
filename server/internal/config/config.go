// Package config loads server settings from the environment.
//
// In development, variables can live in server/.env (loaded automatically).
// In production, set them in the process environment as usual.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Config holds product API settings read from the environment.
type Config struct {
	Port               string `env:"PORT" envDefault:"8080"`
	SupabaseProjectURL string `env:"SUPABASE_PROJECT_URL,notEmpty"`
	DatabaseURL        string `env:"DATABASE_URL,notEmpty"`
	CORSOrigin         string `env:"CORS_ORIGIN" envDefault:"http://localhost:5174"`
}

// Load reads optional server/.env then parses environment variables into Config.
func Load() (Config, error) {
	loadDotEnv()

	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}

	cfg.SupabaseProjectURL = normalizeSupabaseURL(cfg.SupabaseProjectURL)
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

// loadDotEnv loads server/.env when present. Missing files are ignored so
// production deployments that inject env vars directly keep working.
func loadDotEnv() {
	paths := []string{".env", filepath.Join("server", ".env")}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		_ = godotenv.Load(path)
		return
	}
}
