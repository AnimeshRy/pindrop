package toolinstall

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// recordName is the file recording what setup installed, inside PINDROP_HOME.
const recordName = "installed.json"

// recordSchema is the layout version of that file.
const recordSchema = 1

// A Record is what `pindrop setup` has installed.
//
// It exists so that an install is idempotent without re-reading ~200 MB of
// binaries: knowing the version and digest that were installed is enough to skip
// a tool, which is what makes a second `pindrop setup` on a provisioned machine
// finish instantly and make no network requests at all. That property is the
// entire offline story, and it is why there is no --offline flag.
//
// It is a cache of a decision, never a source of truth about integrity: a binary
// is verified when it is installed, and `pindrop setup --check` re-verifies by
// running each tool rather than by trusting this file.
type Record struct {
	Schema int                  `json:"schema"`
	Tools  map[string]Installed `json:"tools"`
}

// Installed describes one installed tool.
type Installed struct {
	Version     string    `json:"version"`
	SHA256      string    `json:"sha256"`
	InstalledAt time.Time `json:"installedAt"`
}

// LoadRecord reads the install record from home.
//
// A missing, unreadable, or unrecognized file yields an empty record rather than
// an error. Every consequence of being wrong here is recoverable — at worst a tool
// is reported as foreign and needs --force — whereas failing setup because a
// cache file is corrupt would strand the user with no way forward.
func LoadRecord(home string) *Record {
	empty := &Record{Schema: recordSchema, Tools: map[string]Installed{}}

	// #nosec G304 -- the path is PINDROP_HOME plus a constant file name.
	raw, err := os.ReadFile(filepath.Join(home, recordName))
	if err != nil {
		return empty
	}

	var r Record
	if err := json.Unmarshal(raw, &r); err != nil || r.Schema != recordSchema {
		return empty
	}
	if r.Tools == nil {
		r.Tools = map[string]Installed{}
	}
	return &r
}

// Get returns the record for a tool.
func (r *Record) Get(name string) (Installed, bool) {
	installed, ok := r.Tools[name]
	return installed, ok
}

// Set records a successful install. It does not write to disk; call [Record.Save].
func (r *Record) Set(name, version, digest string) {
	if r.Tools == nil {
		r.Tools = map[string]Installed{}
	}
	r.Tools[name] = Installed{
		Version:     version,
		SHA256:      digest,
		InstalledAt: time.Now().UTC(),
	}
}

// Forget drops a tool from the record.
func (r *Record) Forget(name string) { delete(r.Tools, name) }

// Save writes the record into home, atomically.
//
// Written through a temporary file and renamed so that an interrupted save leaves
// the previous record intact rather than a truncated one — which would report
// every tool as foreign and demand --force to proceed.
func (r *Record) Save(home string) error {
	if err := os.MkdirAll(home, 0o750); err != nil {
		return fmt.Errorf("creating %s: %w", home, err)
	}
	r.Schema = recordSchema

	encoded, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the install record: %w", err)
	}
	encoded = append(encoded, '\n')

	tmp, err := os.CreateTemp(home, recordName+".*")
	if err != nil {
		return fmt.Errorf("creating a temporary file in %s: %w", home, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing the install record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing the install record: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("setting permissions on the install record: %w", err)
	}

	if err := os.Rename(tmpPath, filepath.Join(home, recordName)); err != nil {
		return fmt.Errorf("saving the install record: %w", err)
	}
	return nil
}
