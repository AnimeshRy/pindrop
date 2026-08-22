package cliauth

import (
	"strings"
	"testing"
)

func TestCallbackSuccessPage(t *testing.T) {
	t.Parallel()
	html := callbackSuccessPage()
	if !strings.Contains(html, "Pindrop") {
		t.Fatal("expected branding")
	}
	if !strings.Contains(html, "signed in") {
		t.Fatal("expected success message")
	}
}

func TestCallbackErrorPage(t *testing.T) {
	t.Parallel()
	html := callbackErrorPage("access_denied", "User cancelled")
	if !strings.Contains(html, "Sign-in failed") {
		t.Fatal("expected error heading")
	}
	if !strings.Contains(html, "access_denied") {
		t.Fatal("expected escaped error code")
	}
}

func TestCredentialsDisplay(t *testing.T) {
	t.Parallel()
	c := Credentials{Email: "jane@example.com", Provider: ProviderGitHub}
	if c.DisplayEmail() != "jane@example.com" {
		t.Fatal(c.DisplayEmail())
	}
	if c.DisplayProvider() != "GitHub" {
		t.Fatal(c.DisplayProvider())
	}
}
