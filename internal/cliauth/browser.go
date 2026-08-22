package cliauth

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// AutoOpenBrowser reports whether Login should launch the system browser.
//
// WSL often mangles long OAuth URLs when forwarding them to Windows; Login
// shows the authorize link for manual opening instead.
func AutoOpenBrowser() bool {
	return !wsl()
}

// openURL launches the system default browser at url.
//
// Failure is not fatal — callers show the URL for manual opening.
func openURL(url string) error {
	for _, args := range browserCommands(url) {
		if len(args) == 0 {
			continue
		}
		name := args[0]
		if _, err := exec.LookPath(name); err != nil {
			// cmd.exe is not found via LookPath on some WSL installs; try anyway.
			if name != "cmd.exe" {
				continue
			}
		}
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Start(); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no browser launcher available on this system")
}

func browserCommands(url string) [][]string {
	switch runtime.GOOS {
	case "darwin":
		return [][]string{{"open", url}}
	case "windows":
		return [][]string{{"rundll32", "url.dll,FileProtocolHandler", url}}
	default:
		return [][]string{{"xdg-open", url}}
	}
}

func wsl() bool {
	if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "" {
		return true
	}
	raw, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(raw)), "microsoft")
}
