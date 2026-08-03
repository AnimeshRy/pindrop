package trivy

// This file mirrors the subset of Trivy's JSON report (SchemaVersion 2) that
// Pindrop consumes.
//
// These structs are hand-written on purpose. Importing
// github.com/aquasecurity/trivy/pkg/types to reuse its Report type pulls in
// fanal/types, go-containerregistry, and sbom/core, which transitively drags in
// most of Trivy's ~500-module dependency graph — for the sake of about sixty
// lines of struct definitions. See docs/decisions/0002-trivy-subprocess.md.
//
// Decoding is deliberately defensive. Almost every field in Trivy's schema is
// omitempty, and the Results array is absent entirely when a scan finds
// nothing. Trivy documents only VulnerabilityID, PkgName, InstalledVersion, and
// Severity as always populated; everything else may be missing.

// report is the top level of `trivy --format json` output.
type report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Results       []result `json:"Results"`
}

// result groups findings by scan target — one lockfile, one config file, and
// so on. Class distinguishes what kind of findings the entry carries.
type result struct {
	// Target is the file or package group the findings belong to, relative to
	// the scan root.
	Target string `json:"Target"`
	// Class is one of os-pkgs, lang-pkgs, config, secret, license,
	// license-file, custom, or unknown.
	Class string `json:"Class"`
	// Type is the concrete ecosystem or format, such as "npm" or "dockerfile".
	Type string `json:"Type"`

	Vulnerabilities   []vulnerability    `json:"Vulnerabilities"`
	Misconfigurations []misconfiguration `json:"Misconfigurations"`
	Secrets           []secret           `json:"Secrets"`
	Licenses          []license          `json:"Licenses"`
}

// vulnerability is a CVE detected in a dependency.
type vulnerability struct {
	VulnerabilityID  string     `json:"VulnerabilityID"`
	PkgName          string     `json:"PkgName"`
	PkgIdentifier    identifier `json:"PkgIdentifier"`
	InstalledVersion string     `json:"InstalledVersion"`
	FixedVersion     string     `json:"FixedVersion"`
	Severity         string     `json:"Severity"`
	Title            string     `json:"Title"`
	Description      string     `json:"Description"`
	PrimaryURL       string     `json:"PrimaryURL"`
	References       []string   `json:"References"`
}

// identifier carries the Package URL, when Trivy can derive one.
type identifier struct {
	PURL string `json:"PURL"`
}

// misconfiguration is an insecure infrastructure-as-code setting.
//
// Verified against Trivy v0.72.0: the check identifier arrives as ID (for
// example "DS-0002"). Older documentation mentions an AVDID field; it is not
// present in current output.
type misconfiguration struct {
	ID            string        `json:"ID"`
	Title         string        `json:"Title"`
	Description   string        `json:"Description"`
	Message       string        `json:"Message"`
	Resolution    string        `json:"Resolution"`
	Severity      string        `json:"Severity"`
	PrimaryURL    string        `json:"PrimaryURL"`
	References    []string      `json:"References"`
	CauseMetadata causeMetadata `json:"CauseMetadata"`
}

// causeMetadata locates a misconfiguration within its source file.
type causeMetadata struct {
	StartLine int  `json:"StartLine"`
	EndLine   int  `json:"EndLine"`
	Code      code `json:"Code"`
}

// code holds the source lines Trivy captured around a misconfiguration.
type code struct {
	Lines []codeLine `json:"Lines"`
}

type codeLine struct {
	Number  int    `json:"Number"`
	Content string `json:"Content"`
}

// secret is a credential detected in the source tree. Trivy redacts the
// matched value, so Match is a masked excerpt rather than the raw secret.
type secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

// license is a dependency license that violates policy.
//
// Unlike the other types here, these field names come from Trivy's
// DetectedLicense struct rather than from a captured report: the license
// scanner emits an empty license-file result for the fixtures we have.
type license struct {
	Severity   string  `json:"Severity"`
	Category   string  `json:"Category"`
	PkgName    string  `json:"PkgName"`
	FilePath   string  `json:"FilePath"`
	Name       string  `json:"Name"`
	Confidence float64 `json:"Confidence"`
	Link       string  `json:"Link"`
}
