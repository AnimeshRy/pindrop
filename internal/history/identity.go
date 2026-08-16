package history

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/AnimeshRy/pindrop/internal/vcs"
)

// dbFileMode is the permission for the SQLite database file.
const dbFileMode = 0o600

func canonicalRoot(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %q to an absolute path: %w", path, err)
	}

	base := abs
	if info, err := vcs.Inspect(abs); err == nil && info.Root != "" {
		base = info.Root
	}
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		base = resolved
	}
	if base, err = filepath.Abs(base); err != nil {
		return "", fmt.Errorf("resolving %q to an absolute path: %w", path, err)
	}
	return filepath.Clean(base), nil
}

func repoIDFor(canonical string) RepoID {
	sum := sha256.Sum256([]byte("path:" + canonical))
	return RepoID("r_" + hex.EncodeToString(sum[:16]))
}

func mintRunID(finished time.Time) (RunID, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generating a run identifier: %w", err)
	}
	return RunID(finished.UTC().Format(runIDLayout) + "-" + hex.EncodeToString(suffix[:])), nil
}

func mintRunIDAfter(finished time.Time, newest RunID) (RunID, error) {
	for range 4 {
		id, err := mintRunID(finished)
		if err != nil {
			return "", err
		}
		if newest == "" || id > newest {
			return id, nil
		}
		if at, ok := newest.Time(); ok && !finished.After(at) {
			finished = at.Add(time.Second)
			continue
		}
		finished = finished.Add(time.Second)
	}
	return "", errors.New("generating a run identifier: the clock is too far behind this repository's newest run")
}

func validateRepoID(id RepoID) error {
	if !id.Valid() {
		return fmt.Errorf("%q is not a repository id (expected r_ followed by 32 hex characters): %w", string(id), ErrNotFound)
	}
	return nil
}

func validateRunID(id RunID) error {
	if !id.Valid() {
		return fmt.Errorf("%q is not a run id (expected 20060102T150405Z-abcdef12): %w", string(id), ErrNotFound)
	}
	return nil
}

func repoName(root string) string {
	return filepath.Base(root)
}
