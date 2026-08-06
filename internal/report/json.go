package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/AnimeshRy/pindrop/internal/buildinfo"
	"github.com/AnimeshRy/pindrop/internal/scan"
)

// DocumentSchemaVersion identifies the layout of Pindrop's JSON report.
//
// It is written into every document so that consumers — the dashboard, the
// server ingest endpoint, a user's CI script — can detect an incompatible
// producer instead of silently misreading fields. Bump it on any breaking
// change to the shape.
const DocumentSchemaVersion = 1

// A Document is Pindrop's own JSON report: the complete, unabridged result of a
// scan, suitable for machine consumption and for re-serving over the API.
type Document struct {
	SchemaVersion int       `json:"schemaVersion"`
	GeneratedAt   time.Time `json:"generatedAt"`
	Tool          Tool      `json:"tool"`

	// Scans records one entry per scanner that ran, with its timing.
	Scans []ScanSummary `json:"scans"`

	// Findings is the merged, severity-ordered set across all scanners: one
	// entry per issue, not per scanner report. It is never null — a clean scan
	// produces an empty array, so consumers do not need a null check.
	Findings []scan.Finding `json:"findings"`
}

// Tool identifies the producer of a [Document].
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScanSummary is the per-scanner metadata for one run.
type ScanSummary struct {
	Scanner   string    `json:"scanner"`
	Target    string    `json:"target"`
	StartedAt time.Time `json:"startedAt"`

	DurationMS int64 `json:"durationMs"`

	// Findings is how many findings this scanner reported on its own, before
	// cross-tool merging and before any severity filter. It therefore does not
	// sum to len(Document.Findings), and is not meant to: the gap between the
	// two is the whole point. Two scanners reporting 8 and 6 against 8 merged
	// issues is the product working.
	Findings int `json:"findings"`
}

// NewDocument assembles a [Document] from raw scan results.
func NewDocument(results []scan.Result) Document {
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

	findings := scan.Findings(results)
	if findings == nil {
		findings = []scan.Finding{}
	}

	return Document{
		SchemaVersion: DocumentSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Tool:          Tool{Name: buildinfo.Name, Version: buildinfo.Version()},
		Scans:         scans,
		Findings:      findings,
	}
}

// JSON writes doc, indented for readability. Pindrop reports get committed to
// repositories and diffed in pull requests, so the extra bytes buy more than they
// cost.
func JSON(w io.Writer, doc Document) error {
	// A caller that filtered the findings down to nothing can leave a nil slice
	// here, and the schema promises an array.
	if doc.Findings == nil {
		doc.Findings = []scan.Finding{}
	}

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
// build does not understand.
func DecodeDocument(r io.Reader) (Document, error) {
	var doc Document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decoding report: %w", err)
	}
	if doc.SchemaVersion != DocumentSchemaVersion {
		return Document{}, fmt.Errorf(
			"report schema version %d is not supported (this build reads version %d)",
			doc.SchemaVersion, DocumentSchemaVersion)
	}
	return doc, nil
}
