package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// ConfigName is the per-repository configuration file Pindrop looks for in the
// directory being scanned.
//
// JSON rather than YAML or TOML, which both cost a dependency. CLAUDE.md is
// explicit that every dependency in a security tool is supply-chain surface,
// and the module has one direct dependency today; a YAML parser is a large
// attack surface with its own CVE history, pulled in to read a list of strings.
//
// The cost is real — JSON has no comments — and is bought off by permitting a
// single "$comment" key, so DisallowUnknownFields can stay on and a typo is
// still an error.
const ConfigName = ".pindrop.json"

// configSchemaVersion is the layout this build understands.
const configSchemaVersion = 1

// config is the on-disk shape of [ConfigName].
type config struct {
	// Comment exists so a JSON config can be annotated at all. It is ignored.
	Comment string `json:"$comment,omitempty"`

	// Version guards against a future incompatible layout. Absent means 1, so
	// a minimal config need not carry boilerplate.
	Version *int `json:"version,omitempty"`

	Exclude configExclude `json:"exclude,omitzero"`
}

// configExclude is the "exclude" block.
type configExclude struct {
	Dirs  []string `json:"dirs,omitempty"`
	Files []string `json:"files,omitempty"`

	// ReplaceDefaults drops the built-in set instead of adding to it.
	//
	// Spelled as a positive that defaults to false so that Go's zero value is
	// the safe, additive behaviour and no pointer is needed. Additive is the
	// right default because the built-in set carries .git, which is
	// load-bearing for fingerprint stability rather than merely noise
	// reduction — a secret inside a packfile has a path that churns on every
	// gc, and the path is a fingerprint input.
	ReplaceDefaults bool `json:"replaceDefaults,omitempty"`
}

// loadConfig reads the configuration for a scan.
//
// explicit is the value of --config; when empty, [ConfigName] is looked for in
// the target directory. A missing default file is not an error — a repository
// need not have one — but a missing explicit one is, because the user named a
// path and silently ignoring it would apply exclusions they did not ask for.
func loadConfig(targetPath, explicit string) (config, error) {
	path := explicit
	if path == "" {
		path = filepath.Join(targetPath, ConfigName)
	}

	f, err := os.Open(path) //nolint:gosec // the path is the user's own config
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && explicit == "" {
			return config{}, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return config{}, fmt.Errorf("no config file at %s", path)
		}
		return config{}, fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	cfg, err := decodeConfig(f, path)
	if err != nil {
		return config{}, err
	}
	return cfg, nil
}

// decodeConfig parses a config, reporting problems in terms the author can act
// on. name is used only in messages.
func decodeConfig(r io.Reader, name string) (config, error) {
	body, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return config{}, fmt.Errorf("reading %s: %w", name, err)
	}

	dec := json.NewDecoder(strings.NewReader(string(body)))
	// A typo in a key would otherwise be silently ignored, which for an
	// exclusion file means scanning something the user believes is excluded.
	dec.DisallowUnknownFields()

	var cfg config
	if err := dec.Decode(&cfg); err != nil {
		return config{}, configError(body, name, err)
	}

	if v := cfg.Version; v != nil && *v != configSchemaVersion {
		return config{}, fmt.Errorf(
			"%s: version %d is newer than this build of pindrop understands (%d) — "+
				"upgrade pindrop, or remove the \"version\" field to use the v%d schema",
			name, *v, configSchemaVersion, configSchemaVersion)
	}
	return cfg, nil
}

// configError turns a decoder error into an actionable message, resolving a
// byte offset into a line and column. Our users are not security engineers, and
// "invalid character '}'" with no position is not something to act on.
func configError(body []byte, name string, err error) error {
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		line, col := lineCol(body, syntax.Offset)
		return fmt.Errorf("%s is not valid JSON (line %d, column %d): %s",
			name, line, col, syntax.Error())
	}

	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		line, col := lineCol(body, typeErr.Offset)
		return fmt.Errorf("%s: field %q expects %s but found %s (line %d, column %d)",
			name, typeErr.Field, typeErr.Type, typeErr.Value, line, col)
	}

	// DisallowUnknownFields reports a plain error; its text already names the
	// field, so surface it with the file and a nudge toward the schema.
	if field, ok := unknownField(err); ok {
		return fmt.Errorf(
			"%s: unknown field %q — known fields are version, exclude.dirs, "+
				"exclude.files and exclude.replaceDefaults",
			name, field)
	}
	return fmt.Errorf("reading %s: %w", name, err)
}

// unknownField extracts the field name from DisallowUnknownFields' error.
func unknownField(err error) (string, bool) {
	const prefix = "json: unknown field "
	msg := err.Error()
	if !strings.HasPrefix(msg, prefix) {
		return "", false
	}
	return strings.Trim(strings.TrimPrefix(msg, prefix), `"`), true
}

// lineCol converts a byte offset into a 1-indexed line and column.
func lineCol(body []byte, offset int64) (line, col int) {
	if offset > int64(len(body)) {
		offset = int64(len(body))
	}

	line, col = 1, 1
	for _, b := range body[:offset] {
		if b == '\n' {
			line, col = line+1, 1
			continue
		}
		col++
	}
	return line, col
}

// resolveExcludes composes the exclusion set for one scan.
//
// The order is defaults, then the config file, then flags, and every step is
// additive: a user adding one project-specific directory must not silently lose
// the built-in set. Replacing is available in exactly two places, and both are
// named for what they do.
func resolveExcludes(cfg config, flagPatterns []string, noDefaults bool) (scan.Excludes, error) {
	var ex scan.Excludes
	if !noDefaults && !cfg.Exclude.ReplaceDefaults {
		ex = scan.DefaultExcludes()
	}

	fromConfig := scan.Excludes{Dirs: cfg.Exclude.Dirs, Files: cfg.Exclude.Files}
	if err := fromConfig.Validate(); err != nil {
		return scan.Excludes{}, fmt.Errorf("%s: %w", ConfigName, err)
	}
	ex = ex.Merge(fromConfig)

	fromFlags, err := scan.ParsePatterns(flagPatterns)
	if err != nil {
		return scan.Excludes{}, fmt.Errorf("--exclude: %w", err)
	}
	return ex.Merge(fromFlags), nil
}
