package cliauth

import (
	"testing"
)

func TestNewPKCEPair(t *testing.T) {
	t.Parallel()

	pair, err := newPKCEPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.Verifier) < 43 {
		t.Fatalf("verifier too short: %d", len(pair.Verifier))
	}
	if pair.Challenge == "" {
		t.Fatal("expected non-empty challenge")
	}
	if pair.Verifier == pair.Challenge {
		t.Fatal("verifier and challenge must differ")
	}
}

func TestNormalizeSupabaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
	}{
		{"https://abc.supabase.co", "https://abc.supabase.co"},
		{"https://abc.supabase.co/rest/v1", "https://abc.supabase.co"},
		{"https://abc.supabase.co/", "https://abc.supabase.co"},
	}
	for _, tc := range tests {
		if got := normalizeSupabaseURL(tc.in); got != tc.want {
			t.Errorf("normalizeSupabaseURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
