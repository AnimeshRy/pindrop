// Package toolpath answers one question: where is the executable for an external
// tool Pindrop shells out to?
//
// It exists because Pindrop ships as a single binary a user drops into
// /usr/local/bin, while the four scanners it drives are separate executables that
// have to come from somewhere. `pindrop setup` installs them into a directory
// this package names, and [Lookup] is how every adapter finds them afterwards.
//
// Like internal/scan, this package imports nothing of ours and nothing beyond a
// handful of stdlib packages. Locating a binary is deliberately separated from
// installing one — internal/toolinstall does that, and depends on this — so that
// the four scanner adapters do not acquire a downloader in their import graph.
package toolpath

import (
	"fmt"
	"os"
	"path/filepath"
)

// HomeEnv names the environment variable that overrides the managed directory.
// It is exported so the CLI can name it in error messages rather than
// hardcoding the string in two places.
const HomeEnv = "PINDROP_HOME"

// dirName is the managed directory's name under the user's home directory.
const dirName = ".pindrop"

// Home returns the directory Pindrop keeps its own machine-global state in —
// today, the scanner binaries `pindrop setup` installs.
//
// PINDROP_HOME wins if set. Otherwise it is ~/.pindrop, on every platform.
//
// The XDG base directory spec is deliberately not followed. A single fixed path
// can be printed literally in every error message, install prompt, and doc, and
// removed with one command a non-expert can be told to run — whereas
// XDG_DATA_HOME resolves differently per platform and per shell, which turns
// "where did it put things" into a support question. ~/.cargo, ~/.rustup and
// ~/.docker set the precedent. See ADR 0011.
//
// Note this is machine-global state, distinct from the per-repository .pindrop/
// directory that holds scan reports. Same name, different level, on purpose.
func Home() (string, error) {
	if dir := os.Getenv(HomeEnv); dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", fmt.Errorf("resolving %s=%q: %w", HomeEnv, dir, err)
		}
		return abs, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating your home directory; set %s to choose one: %w", HomeEnv, err)
	}
	return filepath.Join(home, dirName), nil
}

// Dir returns the directory `pindrop setup` installs scanner binaries into.
// It does not create it; see [EnsureDir].
func Dir() (string, error) {
	home, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "bin"), nil
}

// EnsureDir returns [Dir], creating it if it does not exist.
func EnsureDir() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	return dir, nil
}

// Display renders path with the user's home directory collapsed to ~, for use in
// messages. "~/.pindrop/bin" is what a user can retype; the expanded path is
// noise. It returns path unchanged if it does not lie under the home directory.
func Display(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}

	rel, err := filepath.Rel(home, path)
	if err != nil || rel == ".." || filepath.IsAbs(rel) {
		return path
	}
	if rel == "." {
		return "~"
	}
	// filepath.Rel happily walks upward; anything that does is not under home.
	if len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return path
	}
	return filepath.Join("~", rel)
}
