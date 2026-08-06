package cli

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/AnimeshRy/pindrop/internal/auth"
	"github.com/AnimeshRy/pindrop/internal/httpapi"
)

func resolveServeMode(flag string) (httpapi.Mode, error) {
	raw := strings.TrimSpace(flag)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("PINDROP_MODE"))
	}
	if raw == "" {
		return httpapi.ModeSelfHosted, nil
	}
	switch strings.ToLower(raw) {
	case "self-hosted", "selfhosted":
		return httpapi.ModeSelfHosted, nil
	case "cloud":
		return httpapi.ModeCloud, nil
	default:
		return "", fmt.Errorf("invalid mode %q: use self-hosted or cloud", raw)
	}
}

func resolveSupabaseURL(flag string) string {
	if v := strings.TrimSpace(flag); v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(strings.TrimSpace(os.Getenv("PINDROP_SUPABASE_URL")), "/")
}

func resolvePublishableKey(flag string) string {
	if v := strings.TrimSpace(flag); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("PINDROP_SUPABASE_PUBLISHABLE_KEY"))
}

func buildHTTPServerConfig(mode httpapi.Mode, supabaseURL, publishableKey string, assets fs.FS, resultsPath string) (httpapi.Config, error) {
	cfg := httpapi.Config{
		Assets: assets,
		Source: httpapi.FileSource{Path: resultsPath},
		Mode:   mode,
	}

	if mode != httpapi.ModeCloud {
		return cfg, nil
	}

	if supabaseURL == "" || publishableKey == "" {
		return httpapi.Config{}, fmt.Errorf(`cloud mode requires Supabase settings:
  set PINDROP_SUPABASE_URL (e.g. https://YOUR_PROJECT.supabase.co)
  set PINDROP_SUPABASE_PUBLISHABLE_KEY (sb_publishable_… from Supabase Settings → API Keys)
  or pass --supabase-url and --supabase-publishable-key to pindrop serve`)
	}

	verifier, err := auth.NewVerifier(supabaseURL, nil)
	if err != nil {
		return httpapi.Config{}, fmt.Errorf("creating auth verifier: %w", err)
	}

	cfg.SupabaseURL = supabaseURL
	cfg.PublishableKey = publishableKey
	cfg.Verifier = httpapi.NewAuthAdapter(verifier)
	return cfg, nil
}
