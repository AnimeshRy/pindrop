package cliauth

import (
	"os"
	"testing"
)

func TestAutoOpenBrowser(t *testing.T) {
	t.Parallel()

	if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "" {
		if AutoOpenBrowser() {
			t.Fatal("expected AutoOpenBrowser=false on WSL")
		}
		return
	}

	if !AutoOpenBrowser() {
		t.Fatal("expected AutoOpenBrowser=true outside WSL")
	}
}
