package osv

// This file mirrors the subset of `osv-scanner --format json` output that
// Pindrop consumes. Field names and shapes were captured from OSV-Scanner
// v2.4.0 run against testdata/vulnerable-app, not transcribed from
// documentation — see testdata/report.json.
//
// Hand-written rather than imported. github.com/google/osv-scanner/v2 would
// bring its own extractor tree, deps.dev clients, and a SQLite driver
// (modernc.org/libc) along with it, for the sake of these struct definitions.
// The same reasoning as docs/decisions/0002-trivy-subprocess.md.
//
// Decode defensively: every array here is absent rather than empty when it has
// no members, and advisory records vary in which optional fields they carry
// depending on which database supplied them.

// report is the top level of the JSON output.
type report struct {
	Results []result `json:"results"`
}

// result groups findings by the file they were discovered in — one lockfile,
// one SBOM, one manifest.
type result struct {
	Source   source         `json:"source"`
	Packages []packageEntry `json:"packages"`
}

// source identifies the scanned file.
//
// Path is **absolute**, unlike Trivy's target which is relative to the scan
// root. Converting it is not cosmetic: the manifest path is a fingerprint input,
// so leaving it absolute would give the same vulnerability a different identity
// on every machine and stop it merging with Trivy's report of the same problem.
type source struct {
	Path string `json:"path"`
	// Type is "lockfile", "sbom", "os", or "git".
	Type string `json:"type"`
}

// packageEntry is one dependency together with what was found against it.
type packageEntry struct {
	Package         packageInfo     `json:"package"`
	Groups          []group         `json:"groups"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

// packageInfo is the installed dependency as resolved from the lockfile.
type packageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Ecosystem uses OSV's vocabulary ("npm", "Go", "PyPI", "crates.io"),
	// which differs from Trivy's. scan.CanonicalEcosystem reconciles them.
	Ecosystem string `json:"ecosystem"`
}

// group clusters advisories that OSV-Scanner considers the same underlying
// issue, and is the only place a severity figure is reported.
//
// A group can hold several IDs: lodash 4.17.20 yields one group whose IDs are
// GHSA-35jh-r3h4-6jhm and GHSA-r5fr-rjxr-66jc. MaxSeverity applies to the group
// as a whole, so every vulnerability in it shares a severity.
type group struct {
	IDs     []string `json:"ids"`
	Aliases []string `json:"aliases"`
	// MaxSeverity is a CVSS base score rendered as a decimal string ("7.7"),
	// not a severity word. OSV has no qualitative severity vocabulary of its
	// own; see severity in convert.go.
	MaxSeverity string `json:"max_severity"`
}

// vulnerability is one advisory record in OSV schema form.
type vulnerability struct {
	// ID is the primary identifier, typically GHSA-* even for advisories that
	// have a CVE. The CVE, when one exists, is in Aliases.
	ID string `json:"id"`

	// Aliases are this specific advisory's other identifiers. Prefer these over
	// the enclosing group's aliases: a group unions the aliases of every
	// advisory in it, so using them would attribute one advisory's CVE to
	// another.
	Aliases []string `json:"aliases"`

	Summary    string      `json:"summary"`
	Details    string      `json:"details"`
	Affected   []affected  `json:"affected"`
	References []reference `json:"references"`
}

// affected describes one package-and-version-range this advisory applies to. An
// advisory covering several packages, or several major lines of one package, has
// an entry per combination — lodash's records carry five.
type affected struct {
	Package packageIdent   `json:"package"`
	Ranges  []versionRange `json:"ranges"`
}

// packageIdent names the affected package and carries its Package URL.
type packageIdent struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
}

// versionRange is a sequence of introduced/fixed events over a version ordering.
type versionRange struct {
	// Type is "SEMVER", "ECOSYSTEM", or "GIT". GIT ranges carry commit hashes
	// rather than versions and are not useful as a fix target.
	Type   string       `json:"type"`
	Events []rangeEvent `json:"events"`
}

// rangeEvent is one boundary in a version range. Exactly one field is set.
type rangeEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// reference is a link supplied by the advisory database.
type reference struct {
	// Type is ADVISORY, WEB, REPORT, FIX, PACKAGE, and so on.
	Type string `json:"type"`
	URL  string `json:"url"`
}
