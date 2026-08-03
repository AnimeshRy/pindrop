// Package web embeds the built dashboard single-page application.
//
// The embed directive must live here rather than under internal/, because an
// embed pattern cannot reference paths outside its own package directory. This
// file is therefore the one piece of Go code that sits alongside the pnpm
// project.
package web

import (
	"embed"
	"errors"
	"io/fs"
)

// distFS holds the Vite build output.
//
// The all: prefix includes files beginning with "." or "_", which Vite emits
// and a plain embed would silently skip. web/dist/.gitkeep is committed so this
// directive resolves on a fresh clone, before anyone has run `make web`.
//
//go:embed all:dist
var distFS embed.FS

// ErrNotBuilt reports that the binary was compiled without a dashboard build.
// Callers should surface it as guidance to run the frontend build rather than
// as an internal failure.
var ErrNotBuilt = errors.New("dashboard assets are not built")

// FS returns the dashboard file tree rooted at the build output directory.
//
// It returns [ErrNotBuilt] when the binary was compiled before the frontend was
// built, which is the normal state of a fresh checkout.
func FS() (fs.FS, error) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, err
	}

	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, ErrNotBuilt
	}
	return sub, nil
}
