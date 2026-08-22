package tui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/AnimeshRy/pindrop/internal/cliauth"
)

func TestLoginModelManualURLView(t *testing.T) {
	t.Parallel()

	authURL := "https://example.supabase.co/auth/v1/authorize?code_challenge=abc&code_challenge_method=S256&provider=github&redirect_to=http%3A%2F%2F127.0.0.1%3A1%2Fcallback"
	m := loginModel{
		stage:  cliauth.LoginStageManualURL,
		detail: authURL,
		styles: newStyles(false),
	}
	view := m.View()
	if strings.Contains(view, "authorize?") {
		t.Fatalf("authorize URL must not be embedded in bubbletea view (truncates), got:\n%s", view)
	}
	if !strings.Contains(view, "printed below") {
		t.Fatalf("expected pointer to URL below frame, got:\n%s", view)
	}
}

func TestLoginSessionManualURLPrintsFullURL(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	authURL := "https://example.supabase.co/auth/v1/authorize?code_challenge=abc&code_challenge_method=S256&provider=github&redirect_to=http%3A%2F%2F127.0.0.1%3A1%2Fcallback"
	s := StartLogin("github", Options{Out: &buf, Mode: ModeAnimated, Color: false})
	s.Progress(cliauth.LoginStageManualURL, authURL)
	s.Stop()

	out := buf.String()
	if !strings.Contains(out, authURL) {
		t.Fatalf("expected full auth URL in output, got:\n%s", out)
	}
	if !strings.Contains(out, "provider=github") {
		t.Fatal("expected provider query param in printed URL")
	}
}
