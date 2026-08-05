package scan

import (
	"strings"
)

// Canonicalization exists so that two tools describing one problem produce one
// fingerprint.
//
// Nothing here is cosmetic. Trivy reports the npm cross-spawn flaw as
// CVE-2024-21538 in ecosystem "npm"; OSV-Scanner reports it as
// GHSA-3xgq-45jj-v275 in ecosystem "npm" with the CVE in its alias list. Trivy
// calls Go modules "gomod" and versions them "v1.2.3"; OSV calls the same
// ecosystem "Go" and the same version "1.2.3". Fingerprinting the raw values
// yields two issues for one vulnerability — the duplicate the product exists to
// prevent.
//
// The rules below are deliberately narrow. Merging two findings that are not the
// same problem is worse than failing to merge two that are: a missed merge shows
// a duplicate, while a wrong merge hides a real issue behind an unrelated triage
// decision. When in doubt, do not normalize.

// CanonicalAdvisoryID picks one identifier for an advisory that every scanner
// reporting it will agree on.
//
// A CVE ID wins whenever one is available, because it is the only identifier
// namespace that all advisory databases cross-reference. OSV records carry the
// CVE in their aliases; Trivy usually reports it directly. Both therefore
// converge on the same string without Pindrop needing to consult a database or
// compare findings against each other.
//
// The choice depends only on this finding's own identifiers, never on which
// other scanners happened to run. That property is essential: if canonicalization
// consulted the rest of the scan, enabling a new scanner would rewrite the
// identity of existing findings and orphan their triage decisions.
//
// When no CVE is present the reported ID is kept as-is, uppercased. Advisories
// with no CVE (GHSA-only, GO-only) are reported under the same ID by every tool
// that knows about them, so no translation is needed.
func CanonicalAdvisoryID(ruleID string, aliases []string) string {
	best := ""
	for _, id := range append([]string{ruleID}, aliases...) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		// Lowest-sorting CVE, so a finding listing several always resolves to
		// the same one regardless of the order the scanner emitted them.
		if best == "" || id < best {
			best = id
		}
	}
	if best != "" {
		return best
	}
	return strings.ToUpper(strings.TrimSpace(ruleID))
}

// ecosystemAliases maps the vocabularies scanners actually emit onto Package URL
// types (https://github.com/package-url/purl-spec), which serve as the canonical
// names because they are an existing standard rather than one Pindrop invented.
//
// Keys are lowercased before lookup. Both Trivy's names (left of the arrow in
// each comment) and OSV's are covered.
var ecosystemAliases = map[string]string{
	// Go: Trivy "gomod"/"gobinary", OSV "Go".
	"gomod":     "golang",
	"gobinary":  "golang",
	"go":        "golang",
	"go-module": "golang",

	// npm: Trivy distinguishes lockfile flavors, OSV does not.
	"yarn": "npm",
	"pnpm": "npm",

	// Python: Trivy names the tool, OSV names the index.
	"pip":              "pypi",
	"poetry":           "pypi",
	"pipenv":           "pypi",
	"uv":               "pypi",
	"python-pkg":       "pypi",
	"packaging":        "pypi",
	"requirements.txt": "pypi",

	// Java: Trivy names the build file, OSV names the repository.
	"pom":    "maven",
	"gradle": "maven",
	"jar":    "maven",

	// Rust: OSV uses the registry hostname.
	"crates.io": "cargo",
	"rust":      "cargo",

	// Ruby.
	"bundler":  "gem",
	"gemspec":  "gem",
	"rubygems": "gem",

	// PHP.
	"packagist": "composer",

	// .NET.
	"dotnet-core": "nuget",

	// Dart, Erlang/Elixir.
	"pub": "pub",
	"hex": "hex",
}

// CanonicalEcosystem normalizes a package ecosystem name to its Package URL
// type.
//
// Unrecognized values are lowercased and returned unchanged rather than guessed
// at. That keeps operating-system package ecosystems (alpine, debian, redhat)
// working — they need no translation today — and means a scanner emitting a
// vocabulary Pindrop has not seen degrades to "does not merge" instead of
// "merges with the wrong thing".
func CanonicalEcosystem(ecosystem string) string {
	e := strings.ToLower(strings.TrimSpace(ecosystem))
	if canonical, ok := ecosystemAliases[e]; ok {
		return canonical
	}
	return e
}

// CanonicalVersion normalizes a package version for the given canonical
// ecosystem.
//
// Only Go is adjusted, and only by dropping the "v" prefix that the module
// system requires and OSV omits. Version strings elsewhere are left exactly as
// reported: comparing them properly needs per-ecosystem semantics (epochs,
// distribution release suffixes, Maven qualifiers) and getting that wrong merges
// unrelated versions of a package, which is a worse failure than a duplicate.
//
// ecosystem must already be canonical — pass the result of [CanonicalEcosystem].
func CanonicalVersion(ecosystem, version string) string {
	v := strings.TrimSpace(version)
	if ecosystem != "golang" {
		return v
	}
	// Only a bare "vN..." prefix, never a "v" that starts a word, so a version
	// like "voyager-1" is untouched.
	if len(v) > 1 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}
