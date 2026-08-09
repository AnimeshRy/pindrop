package history

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// dirMode is the permission for every directory this package creates, and
// fileMode for every file.
//
// Scan history holds findings: file paths, source snippets, and the shape of a
// private codebase. It is 0o700/0o600 rather than the 0o750 the scanner bin
// directory uses, because unlike a downloaded release binary none of this is
// public.
const (
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

// writeFileAtomic writes data to path so that a reader sees either the previous
// contents or the new ones, never a half-written file.
//
// The temporary file is created in the destination directory rather than in
// os.TempDir, because os.Rename cannot cross a filesystem boundary and ~/.pindrop
// on a separate volume is an ordinary setup, not an exotic one. The deferred
// remove is the cleanup path for every failure after creation; on success it
// removes a name that no longer exists and the error is discarded.
//
// This is roughly the body of (*toolinstall.Record).Save, and stays duplicated
// on purpose: an atomicwrite package would be a util package by another name,
// and repo-layout.md rules those out. Twenty-five lines is the correct price.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("creating a temporary file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, fileMode); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("saving %s: %w", path, err)
	}
	return nil
}

// writeJSONAtomic encodes value and writes it with [writeFileAtomic].
//
// HTML escaping is off to match internal/report: findings carry code snippets,
// and < sequences turn a file a user may well open into noise.
func writeJSONAtomic(path string, value any) error {
	encoded, err := marshalJSON(value)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, encoded)
}

// marshalJSON encodes value in this package's canonical form: indented, no HTML
// escaping, trailing newline.
func marshalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, fmt.Errorf("encoding scan history: %w", err)
	}
	return buf.Bytes(), nil
}
