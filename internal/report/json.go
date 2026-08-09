package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/AnimeshRy/pindrop/internal/buildinfo"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// DocumentSchemaVersion is the version this build writes.
//
// It is written into every document so that consumers — the dashboard, the
// server ingest endpoint, a user's CI script — can detect an incompatible
// producer instead of silently misreading fields. Bump it on any change to the
// shape, and bump [MinReadableSchemaVersion] only on a change that older
// documents cannot survive.
const DocumentSchemaVersion = 2

// MinReadableSchemaVersion is the oldest version this build can decode.
//
// Every field added since is optional, so an older document decodes cleanly
// with the new fields left at their zero values. Reports are written to disk
// and, from Phase 1, kept as durable scan history: refusing to read anything
// but the current version would make a version bump silently destroy a user's
// history, which is the opposite of what a history feature is for.
const MinReadableSchemaVersion = 1

// A Document is Pindrop's own JSON report: the complete, unabridged result of a
// scan, suitable for machine consumption and for re-serving over the API.
type Document struct {
	SchemaVersion int       `json:"schemaVersion"`
	GeneratedAt   time.Time `json:"generatedAt"`
	Tool          Tool      `json:"tool"`

	// RunID is set when this document was persisted to scan history. It is
	// absent from a document that was only rendered to stdout or to a file,
	// because such a run has no durable identity to refer back to.
	RunID string `json:"runId,omitempty"`

	// Repo describes the repository scanned, when it could be determined.
	// It is run metadata, not scanner input — no adapter reads a branch name —
	// which is why it lives here and not on [scan.Target].
	Repo *Repo `json:"repo,omitempty"`

	// Scans records one entry per scanner that ran, with its timing.
	Scans []ScanSummary `json:"scans"`

	// Findings is the flattened, severity-ordered set across all scanners.
	// It is never null: a clean scan produces an empty array, so consumers do
	// not need a null check.
	Findings []scan.Finding `json:"findings"`

	// Status maps fingerprint to lifecycle status as of this run. Present only
	// in persisted documents, since "new since last time" is unanswerable
	// without a previous run to compare against. It is keyed by fingerprint
	// rather than by index so that filtering or reordering [Findings] cannot
	// desynchronize a finding from its status.
	Status map[string]scan.Status `json:"status,omitempty"`
}

// Repo identifies the repository a document describes.
//
// ID is a stable key for grouping runs of the same repository across moves and
// re-clones; Path is where it happened to live for this run and must not be
// used as identity.
type Repo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Path   string `json:"path"`
	Origin string `json:"origin,omitempty"`
	Branch string `json:"branch,omitempty"`
	Commit string `json:"commit,omitempty"`
}

// Tool identifies the producer of a [Document].
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScanSummary is the per-scanner metadata for one run.
type ScanSummary struct {
	Scanner    string    `json:"scanner"`
	Target     string    `json:"target"`
	StartedAt  time.Time `json:"startedAt"`
	DurationMS int64     `json:"durationMs"`
	Findings   int       `json:"findings"`
}

// NewDocument assembles a [Document] from raw scan results.
func NewDocument(results []scan.Result) Document {
	findings := scan.Findings(results)
	if findings == nil {
		findings = []scan.Finding{}
	}

	return Document{
		SchemaVersion: DocumentSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Tool:          Tool{Name: buildinfo.Name, Version: buildinfo.Version()},
		Scans:         newScanSummaries(results),
		Findings:      findings,
	}
}

// newScanSummaries projects results down to their per-scanner metadata. It is
// shared with [Table], so that the timing lines a user reads and the timing a
// document records can never drift apart.
func newScanSummaries(results []scan.Result) []ScanSummary {
	scans := make([]ScanSummary, 0, len(results))
	for _, r := range results {
		scans = append(scans, ScanSummary{
			Scanner:    r.Scanner,
			Target:     r.Target.Path,
			StartedAt:  r.StartedAt,
			DurationMS: r.Duration.Milliseconds(),
			Findings:   len(r.Findings),
		})
	}
	return scans
}

// JSON writes results as a [Document], indented for readability. Pindrop
// reports get committed to repositories and diffed in pull requests, so the
// extra bytes buy more than they cost.
func JSON(w io.Writer, results []scan.Result) error {
	return encodeDocument(w, NewDocument(results))
}

// encodeDocument writes doc in Pindrop's canonical JSON encoding.
func encodeDocument(w io.Writer, doc Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Findings can contain code snippets with characters that would otherwise
	// be escaped into unreadable \u sequences.
	enc.SetEscapeHTML(false)

	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("writing JSON report: %w", err)
	}
	return nil
}

// DecodeDocument reads a [Document] from r, rejecting a schema version this
// build cannot understand.
//
// The accepted range is [MinReadableSchemaVersion, DocumentSchemaVersion]. The
// two failure directions are different problems with different fixes, so they
// get different messages: a document from the future needs a newer pindrop,
// while one from too far in the past needs a fresh scan.
func DecodeDocument(r io.Reader) (Document, error) {
	var doc Document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decoding report: %w", err)
	}

	switch v := doc.SchemaVersion; {
	case v == 0:
		// Zero means the field was missing, since no version was ever numbered
		// 0. Reporting that as "too old" would send the user looking for a
		// pindrop release that never existed, when the likelier truth is that
		// this is not a pindrop report at all.
		return Document{}, fmt.Errorf(
			"this file has no schemaVersion, so it is not a pindrop report — " +
				"regenerate it with: pindrop scan . --format json --out <file>")
	case v < MinReadableSchemaVersion:
		return Document{}, fmt.Errorf(
			"report schema version %d was written by an older pindrop and can no longer be read "+
				"(this build reads versions %d through %d) — run a fresh scan to replace it",
			v, MinReadableSchemaVersion, DocumentSchemaVersion)
	case v > DocumentSchemaVersion:
		return Document{}, fmt.Errorf(
			"report schema version %d was written by a newer pindrop than this one "+
				"(this build reads versions %d through %d) — upgrade pindrop to read it",
			v, MinReadableSchemaVersion, DocumentSchemaVersion)
	}

	return doc, nil
}
