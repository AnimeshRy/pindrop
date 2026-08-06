package trufflehog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"strings"

	"github.com/AnimeshRy/pindrop/internal/scan"
)

// digestLen is the number of hex characters kept from the secret digest. Long
// enough that two different credentials in one file will not collide, short
// enough to sit in a table cell.
const digestLen = 16

// convert maps decoded TruffleHog findings into Pindrop's model.
//
// verified reports whether the scan actually requested verification, which the
// records themselves cannot express — see [severity].
func convert(results []finding, root string, verified bool) []scan.Finding {
	findings := make([]scan.Finding, 0, len(results))
	for _, res := range results {
		if !actionable(res) {
			continue
		}
		findings = append(findings, secretFinding(res, root, verified))
	}

	// Second pass, as in every other adapter: the fingerprint is derived from the
	// assembled finding, so it cannot be set while building it.
	for i := range findings {
		findings[i].Fingerprint = scan.Fingerprint(findings[i])
	}

	return findings
}

// secretFinding builds one normalized finding.
//
// No Aliases are populated, and that is a decision rather than the omission
// CLAUDE.md warns about. Aliases exist so that two tools naming one advisory
// differently reach the same fingerprint, which works because advisory
// namespaces are shared and published. A credential has no such second
// identifier: TruffleHog reports only its own detector name, and there is no
// cross-engine namespace in which "AWS" and Trivy's "aws-access-key-id" are
// known to be the same check. Inventing that mapping here would be
// canonicalization that depends on which scanners ran, which ADR 0006 forbids.
func secretFinding(res finding, root string, verified bool) scan.Finding {
	return scan.Finding{
		Scanner:  Name,
		RuleID:   res.DetectorName,
		Category: scan.CategorySecret,
		Severity: severity(res, verified),
		Title:    title(res),
		Message:  message(res, verified),
		Location: scan.Location{
			Path:      relativePath(res.SourceMetadata.Data.Filesystem, root),
			StartLine: line(res.SourceMetadata.Data.Filesystem),
			Snippet:   snippet(res),
		},
		References: references(res),
	}
}

// snippet returns the value that distinguishes this credential from another hit
// of the same detector in the same file.
//
// It is a digest of the secret, never the secret and never TruffleHog's own
// Redacted rendering. Two properties drive that choice.
//
// The plaintext cannot be stored. Pindrop writes findings to a report file and
// serves them over HTTP, so a Finding carrying Raw would turn a secret-scanning
// run into a second copy of every secret it found.
//
// Redacted cannot be used either, because it is per-detector implementation
// rather than schema — the captured fixture has it populated for PrivateKey and
// AWS and empty for four other detectors. Snippet is a fingerprint input, so
// keying on a conditional means the day any detector starts or stops populating
// Redacted, every finding from it changes identity and its triage state orphans.
// That would be a data migration triggered by somebody else's release. Redacted
// still reaches the user, via [message], which is not an identity input.
//
// Raw rather than RawV2: RawV2 is composite for multi-part detectors and is
// populated by only some of them, so digesting it would reintroduce exactly the
// version coupling this function exists to avoid.
func snippet(res finding) string {
	if res.Raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(res.Raw))
	return "sha256:" + hex.EncodeToString(sum[:])[:digestLen]
}

// severity grades a detection.
//
// requested reports whether verification was asked for, and it is load-bearing:
// with --no-verification every record is Verified=false with no
// VerificationError, which is byte-identical to "the issuer was asked and said
// this key is not live". Without that third input the two would grade the same,
// and the second is much weaker evidence than the first.
//
// Nothing maps to SeverityUnknown. Unknown is for a tool vocabulary we failed to
// parse; here the value is absent by design and we know exactly what its absence
// means. Unknown also ranks 0, so using it would sort every secret below every
// informational finding — burying the category the adapter exists to add.
func severity(res finding, requested bool) scan.Severity {
	if !requested {
		// Detected, and nothing was claimed either way. High rather than
		// critical on purpose: enabling verification must be a visible
		// promotion, and if an unverified hit were already critical then the
		// capability that justified choosing TruffleHog over Gitleaks would make
		// no difference to the output.
		return scan.SeverityHigh
	}

	switch {
	case res.Verified:
		// The issuer authenticated it. This is the strongest signal any scanner
		// in Pindrop produces.
		return scan.SeverityCritical
	case res.VerificationError != "":
		// Verification was attempted and broke — a timeout, a rate limit, a
		// network failure. Its evidentiary state is identical to not having
		// asked, so it grades the same. Grading it lower would mean a
		// rate-limited API silently downgrading every real token in the report,
		// a failure that shows up only under load.
		return scan.SeverityHigh
	default:
		// The issuer was asked and the credential is not live: revoked, expired,
		// or a staging value. Still a committed secret-shaped string, and still
		// worth seeing, so medium rather than low — suppressing it is a filter's
		// job, not a grade's.
		return scan.SeverityMedium
	}
}

// actionable reports whether a detection is worth showing.
//
// Every adapter owes its output a filter. TruffleHog's own knobs are a poor fit:
// --filter-entropy applies only to detectors that opt into it, and
// --filter-unverified keeps just the first hit per detector per chunk, which
// would discard the distinct credentials [snippet] works to keep distinct. So
// the filter lives here.
//
// Today it drops only records Pindrop cannot place or identify. That is a thin
// filter, and deliberately so — TruffleHog's detectors are keyed on issuer-
// specific formats rather than generic entropy, which is why scanning this
// repository reports nothing. The hook exists so there is somewhere to put a
// rule the first time a detector proves noisy, rather than discovering the
// convention was skipped.
func actionable(res finding) bool {
	if res.DetectorName == "" {
		return false
	}
	// A record with no filesystem metadata came from a source this adapter did
	// not ask for. Without a path there is no identity, and Fingerprint would
	// merge it with every other pathless hit of the same detector.
	if res.SourceMetadata.Data.Filesystem == nil {
		return false
	}
	if res.SourceMetadata.Data.Filesystem.File == "" {
		return false
	}
	// Nothing to digest means nothing to distinguish it by.
	return res.Raw != ""
}

// title is the short summary shown in a table row.
func title(res finding) string {
	switch {
	case res.Verified:
		return fmt.Sprintf("Verified %s credential", res.DetectorName)
	default:
		return fmt.Sprintf("%s credential", res.DetectorName)
	}
}

// message is the full explanation.
//
// This is where TruffleHog's Redacted rendering surfaces: it is genuinely useful
// for recognizing which key was found, and Message is not a fingerprint input,
// so using it here carries none of the stability cost that using it for identity
// would. ExtraData values are included because they are the detector's own
// context — the AWS account a key belongs to, the host a connection string
// points at — and are what makes a finding recognizable without the secret.
func message(res finding, requested bool) string {
	var b strings.Builder

	if res.DetectorDescription != "" {
		b.WriteString(res.DetectorDescription)
	}

	b.WriteString("\n\n")
	switch {
	case !requested:
		b.WriteString("Not verified: run with --verify-secrets to check whether this credential is live.")
	case res.Verified:
		b.WriteString("Verified live against the issuer.")
	case res.VerificationError != "":
		b.WriteString("Verification failed: " + res.VerificationError)
	default:
		b.WriteString("The issuer reports this credential is not live. It may be revoked or expired.")
	}

	if display := redactedForDisplay(res.Redacted); display != "" {
		b.WriteString("\n\nMatched (redacted): " + display)
	}
	if res.DecoderName != "" && res.DecoderName != "PLAIN" {
		b.WriteString("\n\nFound after " + res.DecoderName + " decoding.")
	}
	for _, k := range sortedKeys(res.ExtraData) {
		if k == rotationGuideKey {
			continue // surfaced as a reference instead
		}
		b.WriteString("\n" + k + ": " + res.ExtraData[k])
	}

	return b.String()
}

// rotationGuideKey is the ExtraData key holding a URL explaining how to rotate
// the credential type that fired.
const rotationGuideKey = "rotation_guide"

// references returns URLs with further detail.
//
// TruffleHog supplies no advisory links, but many detectors carry a rotation
// guide, which is more actionable than an advisory would be: the user's problem
// is not understanding the vulnerability class, it is knowing how to revoke this
// particular kind of key.
func references(res finding) []string {
	guide := res.ExtraData[rotationGuideKey]
	if !strings.HasPrefix(guide, "http://") && !strings.HasPrefix(guide, "https://") {
		return nil
	}
	return []string{guide}
}

// line converts the reported line number, which is 1-based and int64 on the
// wire, into the model's int.
//
// Range-guarded rather than converted directly: a bare int64-to-int conversion
// is a gosec G115 finding, and this is a security product held to its own
// standard. A value that cannot be represented is reported as not line-scoped,
// which is the same thing the model already means by zero.
func line(fs *filesystemMetadata) int {
	if fs == nil || fs.Line <= 0 || fs.Line > math.MaxInt32 {
		return 0
	}
	return int(fs.Line)
}

// relativePath converts TruffleHog's absolute path into one relative to the scan
// root.
//
// Required for identity, not display: the path is a fingerprint input, so a
// finding must not change identity because the repository was checked out
// somewhere else.
func relativePath(fs *filesystemMetadata, root string) string {
	if fs == nil {
		return ""
	}
	sourcePath := fs.File
	if sourcePath == "" {
		return ""
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return filepath.ToSlash(sourcePath)
	}
	absSource, err := filepath.Abs(sourcePath)
	if err != nil {
		return filepath.ToSlash(sourcePath)
	}

	rel, err := filepath.Rel(absRoot, absSource)
	if err != nil {
		return filepath.ToSlash(sourcePath)
	}
	// A path that escapes the root is not something we can express relative to
	// it; keep the original rather than emit a `..` chain.
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(sourcePath)
	}

	return filepath.ToSlash(rel)
}

// redactedDisplayLen caps the rendered match. Chosen so that the longest useful
// label survives intact — "-----BEGIN RSA PRIVATE KEY-----" is 31 characters —
// while no meaningful amount of a key body can follow it.
const redactedDisplayLen = 32

// redactedForDisplay renders TruffleHog's Redacted value for a message.
//
// It is capped rather than passed through, because "redacted" upstream does not
// mean "carries nothing sensitive". For the PrivateKey detector, Redacted is the
// PEM header followed by the first 32 characters of the key body. Those bytes are
// the start of the public modulus rather than the private exponent, so they are
// not a cryptographic disclosure — but two practical problems remain.
//
// A Pindrop report is written to disk and served over HTTP, so anything in it is
// a second copy. And a report containing a live-looking PEM header plus body is a
// string that every other secret scanner will itself detect, which would make
// Pindrop's own output a finding in the next tool that reads it.
//
// Capping keeps what identifies the credential — the PEM label, an AKIA key id, a
// ghp_ prefix — and drops the rest.
func redactedForDisplay(redacted string) string {
	one := oneLine(redacted)
	if one == "" {
		return ""
	}

	runes := []rune(one)
	if len(runes) <= redactedDisplayLen {
		return one
	}
	return string(runes[:redactedDisplayLen]) + "…"
}

// oneLine collapses whitespace so a multi-line value such as a private key
// header does not break a table row.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// sortedKeys returns m's keys in a deterministic order, so that two runs produce
// byte-identical messages.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
