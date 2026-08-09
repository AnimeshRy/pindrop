package toolpath

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Origin names where a resolved executable was found. It is reported by
// [LookupOrigin] so `pindrop setup --check` can tell a user which copy of a tool
// is actually being run — the one diagnostic that explains "I have Trivy but
// Pindrop says it is too old".
type Origin string

// The places a tool binary may live, in the order they are searched.
const (
	// OriginExplicit is a --<tool>-binary value containing a path separator,
	// used verbatim.
	OriginExplicit Origin = "explicit"
	// OriginPath is the user's PATH.
	OriginPath Origin = "PATH"
	// OriginSibling is the directory holding the running pindrop binary.
	OriginSibling Origin = "beside pindrop"
	// OriginManaged is the directory `pindrop setup` installs into.
	OriginManaged Origin = "pindrop setup"
)

// Origins are the places [Lookup] searches, most authoritative first. An empty
// field is skipped.
//
// It is an explicit struct rather than being read from the environment inside
// Lookup so that resolution is a pure function of its inputs. That is what lets
// the precedence rules be tested in parallel subtests — t.Setenv forbids
// t.Parallel, and the conventions require both.
type Origins struct {
	// Explicit is the user's --<tool>-binary value. It is honored only when it
	// contains a path separator; a bare name is a PATH lookup, not a path.
	Explicit string
	// PathDirs is normally filepath.SplitList(os.Getenv("PATH")).
	PathDirs []string
	// SelfDir is the directory holding the running executable.
	SelfDir string
	// ManagedDir is the directory `pindrop setup` installs into.
	ManagedDir string
}

// Env builds [Origins] from the process environment, for the tool named by
// binary and the user's override.
//
// A failure to determine the pindrop executable's own location or the managed
// directory is not an error: those origins are simply dropped. Neither is
// something the user can act on, and both are fallbacks behind PATH.
func Env(binary string) Origins {
	o := Origins{
		Explicit: binary,
		PathDirs: filepath.SplitList(os.Getenv("PATH")),
	}

	if self, err := os.Executable(); err == nil {
		o.SelfDir = filepath.Dir(self)
	}
	if managed, err := Dir(); err == nil {
		o.ManagedDir = managed
	}
	return o
}

// Lookup resolves the executable named name against o, returning the first match.
// It is the shared implementation of every adapter's binary resolution.
func Lookup(name string, o Origins) (string, error) {
	path, _, err := LookupOrigin(name, o)
	return path, err
}

// LookupOrigin is [Lookup], additionally reporting which origin supplied the
// result.
//
// The search order is explicit, PATH, beside pindrop, then the managed
// directory. Two properties of that order are deliberate:
//
// PATH beats the managed directory, so a user who has installed Trivy themselves
// keeps using their copy and `pindrop setup` never silently shadows it. The cost
// is that an old tool on PATH still loses to Trivy's version floor rather than
// falling through to ours, which is why `pindrop setup --check` reports the
// winning origin.
//
// The managed directory comes last so that `./bin/pindrop` keeps finding
// `./bin/trivy` through the sibling lookup, which is what makes `make run-scan`
// work without putting ./bin on PATH.
//
// On total failure the PATH error is returned, because "not found in PATH" is the
// failure the user can act on.
func LookupOrigin(name string, o Origins) (string, Origin, error) {
	// An explicit path is a path, not a name to search for. Honoring it verbatim
	// is what makes --trivy-binary /opt/trivy authoritative.
	if o.Explicit != "" && strings.ContainsRune(o.Explicit, os.PathSeparator) {
		path, err := exec.LookPath(o.Explicit)
		return path, OriginExplicit, err
	}

	path, pathErr := lookInDirs(name, o.PathDirs)
	if pathErr == nil {
		return path, OriginPath, nil
	}

	for _, c := range []struct {
		dir    string
		origin Origin
	}{
		{o.SelfDir, OriginSibling},
		{o.ManagedDir, OriginManaged},
	} {
		if c.dir == "" {
			continue
		}
		if found, err := exec.LookPath(filepath.Join(c.dir, name)); err == nil {
			return found, c.origin, nil
		}
	}

	return "", "", pathErr
}

// lookInDirs searches dirs for an executable named name.
//
// The ambient PATH is never read here — that is the caller's job, via [Env] —
// because reading it would make [Lookup] impure and so untestable in parallel.
// The per-candidate check is still delegated to exec.LookPath so that "is this
// executable" means exactly what it means everywhere else in the program.
//
// The returned error deliberately matches exec.LookPath's shape, since adapters
// wrap it into their own UnavailableError and users never see it directly.
func lookInDirs(name string, dirs []string) (string, error) {
	for _, dir := range dirs {
		// POSIX says an empty PATH element means the current directory. Skipping
		// it is deliberate: resolving a scanner out of the directory being
		// scanned is how a scan ends up executing the code it was asked to audit.
		if dir == "" {
			continue
		}
		if found, err := exec.LookPath(filepath.Join(dir, name)); err == nil {
			return found, nil
		}
	}
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}

// ManagedDir returns the directory `pindrop setup` installs into, or a printable
// placeholder if it cannot be determined.
//
// It exists so an adapter's "not found" message can name the third search
// location without every adapter having to handle an error it cannot act on.
func ManagedDir() string {
	dir, err := Dir()
	if err != nil {
		return "the pindrop-managed directory"
	}
	return dir
}
