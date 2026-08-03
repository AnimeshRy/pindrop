// Package buildinfo reports the identity of the running Pindrop binary.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Name is the program name used in output and in report metadata.
const Name = "pindrop"

// Homepage is the project URL, embedded in SARIF reports so consumers can trace
// a finding back to the tool that produced it.
const Homepage = "https://github.com/AnimeshRy/pindrop"

// version is overridden at link time for tagged builds:
//
//	go build -ldflags "-X github.com/AnimeshRy/pindrop/internal/buildinfo.version=v1.2.3"
//
// It is unset for `go install` and local builds, where [Version] falls back to
// the module version or VCS revision that the Go toolchain stamps
// automatically.
var version string

// Version returns the best available description of this build.
//
// It prefers an explicit link-time version, then the module version recorded by
// `go install`, then the VCS revision stamped into a `go build` from a Git
// checkout, and finally "dev".
func Version() string {
	if version != "" {
		return version
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}

	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	if rev := vcsRevision(info); rev != "" {
		return rev
	}
	return "dev"
}

// vcsRevision extracts a short commit description from build settings,
// returning the empty string when the binary was not built from a checkout.
func vcsRevision(info *debug.BuildInfo) string {
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}

	if revision == "" {
		return ""
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified == "true" {
		revision += "-dirty"
	}
	return revision
}

// String returns a one-line description of the binary, its version, and the
// toolchain and platform it was built for.
func String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", Name, Version())
	fmt.Fprintf(&b, " (%s %s/%s)", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return b.String()
}
