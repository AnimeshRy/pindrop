package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
)

// fingerprintLen is the number of hex characters in a fingerprint. SHA-256
// truncated to 16 bytes leaves collision probability negligible at any
// plausible corpus size while staying short enough to print in a table.
const fingerprintLen = 32

// fieldSep separates fingerprint inputs. It is a unit separator rather than a
// printable character so that a value containing it cannot forge a field
// boundary and collide with a different finding.
const fieldSep = "\x1f"

// Fingerprint computes a stable identity for f.
//
// The fingerprint is what lets Pindrop tell "this is the same problem I saw
// last week" from "this is new", which in turn is what makes triage decisions
// durable: mark something a false positive once and it stays marked, even after
// the surrounding code moves.
//
// Two inputs are deliberately excluded:
//
//   - Line numbers. Adding an import at the top of a file shifts every line
//     below it. Including line numbers would report the whole file as fixed and
//     immediately reintroduced, which destroys trust in the tool.
//   - The scanner name. Gitleaks and TruffleHog finding the same key, or Trivy
//     and Grype reporting the same CVE, must collapse into one issue rather
//     than appearing as duplicates.
//
// What does contribute depends on [Category], because different kinds of
// finding have genuinely different notions of identity:
//
//   - Vulnerability and license findings are identified by the rule and the
//     package coordinates. The file and line are incidental — the same CVE in
//     the same package version is the same problem wherever the manifest sits.
//   - Secret, misconfiguration, and code findings are identified by the rule,
//     the file, and the normalized surrounding source.
//
// Fingerprint is deterministic: equal inputs always produce equal output,
// across processes and releases. Changing this function invalidates every
// stored triage decision, so treat it as a data migration.
func Fingerprint(f Finding) string {
	var parts []string

	switch f.Category {
	case CategoryVulnerability, CategoryLicense:
		parts = dependencyIdentity(f)
	case CategorySecret, CategoryMisconfiguration, CategoryCode:
		parts = locationIdentity(f)
	default:
		// An unrecognized category still needs a usable identity. Fall back to
		// the location form, which is the more conservative of the two: it
		// distinguishes findings that the dependency form would merge.
		parts = locationIdentity(f)
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, fieldSep)))
	return hex.EncodeToString(sum[:])[:fingerprintLen]
}

// dependencyIdentity builds fingerprint inputs for package-scoped findings.
//
// The manifest path is included so that the same vulnerable package pinned in
// two different services of a monorepo remains two issues: they are owned by
// different teams and fixed by different pull requests.
// The rule ID and package coordinates are canonicalized first, because the whole
// point of excluding the scanner name is defeated if two tools spell the same
// advisory or the same ecosystem differently. See [CanonicalAdvisoryID].
//
// The installed version is deliberately excluded, for the same reason line
// numbers are. A version is the finding's current state, not its identity: the
// issue is "this dependency, in this manifest, is subject to this advisory".
// Including it meant that bumping golang.org/x/net from v0.35.0 to v0.35.1
// against an advisory not fixed until v0.36.0 changed the fingerprint, so a
// partial upgrade — the most common way these findings actually change —
// reported one issue resolved and one new issue, and orphaned any triage
// decision attached to it. The version remains on [Finding.Package] as
// displayed data, and [Finding.FixedIn] still drives remediation advice.
//
// The cost is that two versions of one package in a single manifest, subject to
// the same advisory, now merge into one finding. That is the right trade and
// the same one [locationIdentity] already makes: merging is recoverable, a
// fingerprint that churns is not.
func dependencyIdentity(f Finding) []string {
	parts := []string{
		"pkg",
		CanonicalAdvisoryID(f.RuleID, f.Aliases),
		normalizePath(f.Location.Path),
	}

	if f.Package == nil {
		return parts
	}

	return append(parts,
		CanonicalEcosystem(f.Package.Ecosystem),
		strings.TrimSpace(f.Package.Name),
	)
}

// locationIdentity builds fingerprint inputs for findings anchored to a place
// in first-party code.
//
// When the scanner reports no snippet there is nothing left to distinguish two
// hits of the same rule in the same file, so they merge. That is the right
// trade: merging is recoverable, whereas a fingerprint that churns on every
// edit is not.
func locationIdentity(f Finding) []string {
	return []string{
		"loc",
		strings.TrimSpace(f.RuleID),
		normalizePath(f.Location.Path),
		NormalizeSnippet(f.Location.Snippet),
	}
}

// normalizePath makes a path comparable across platforms and invocations by
// cleaning it and forcing forward slashes.
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	return path.Clean(strings.ReplaceAll(p, `\`, "/"))
}

// NormalizeSnippet reduces source text to the form used for fingerprinting:
// leading and trailing space removed, and every internal run of whitespace
// collapsed to a single space.
//
// The point is that reformatting is not a code change. Running a formatter,
// re-indenting a block, or converting tabs to spaces must not alter a finding's
// identity. Anything that changes the actual tokens still does.
func NormalizeSnippet(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
