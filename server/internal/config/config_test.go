package config_test

import (
	"testing"

	"github.com/AnimeshRy/pindrop/server/internal/config"
)

func TestLoad_fromEnvironment(t *testing.T) {
	t.Setenv("SUPABASE_PROJECT_URL", "https://abc.supabase.co")
	t.Setenv("DATABASE_URL", "postgresql://localhost:5432/pindrop")
	t.Setenv("PORT", "9090")
	t.Setenv("CORS_ORIGIN", "http://localhost:3000")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.SupabaseProjectURL != "https://abc.supabase.co" {
		t.Fatalf("SupabaseProjectURL = %q", cfg.SupabaseProjectURL)
	}
	if cfg.Port != "9090" {
		t.Fatalf("Port = %q, want 9090", cfg.Port)
	}
	if cfg.CORSOrigin != "http://localhost:3000" {
		t.Fatalf("CORSOrigin = %q", cfg.CORSOrigin)
	}
	if cfg.DatabaseURL != "postgresql://localhost:5432/pindrop" {
		t.Fatalf("DatabaseURL = %q", cfg.DatabaseURL)
	}
}

func TestLoad_requiresSupabaseURL(t *testing.T) {
	t.Setenv("SUPABASE_PROJECT_URL", "")
	t.Setenv("DATABASE_URL", "postgresql://localhost:5432/pindrop")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error when SUPABASE_PROJECT_URL is empty")
	}
}

func TestLoad_stripsRestV1Suffix(t *testing.T) {
	t.Setenv("SUPABASE_PROJECT_URL", "https://abc.supabase.co/rest/v1/")
	t.Setenv("DATABASE_URL", "postgresql://localhost:5432/pindrop")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SupabaseProjectURL != "https://abc.supabase.co" {
		t.Fatalf("SupabaseProjectURL = %q, want base project URL", cfg.SupabaseProjectURL)
	}
}
