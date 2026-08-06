// Package report renders scan results in the formats Pindrop emits.
//
// Three formats serve three audiences: [Table] for a human at a terminal,
// [JSON] for Pindrop's own tooling and the dashboard API, and [SARIF] for
// interoperability with GitHub code scanning and any other tool that speaks the
// OASIS standard.
package report

import (
	"fmt"
	"io"
	"strings"
)

// Format identifies an output encoding.
type Format string

// Supported output formats.
const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// Formats lists every supported format, for use in help text and validation.
var Formats = []Format{FormatTable, FormatJSON, FormatSARIF}

// ParseFormat converts a string to a [Format], accepting any letter case.
func ParseFormat(s string) (Format, error) {
	f := Format(strings.ToLower(strings.TrimSpace(s)))
	for _, valid := range Formats {
		if f == valid {
			return f, nil
		}
	}
	return "", fmt.Errorf("unknown format %q (want one of %s)", s, JoinFormats())
}

// JoinFormats renders the supported formats as a comma-separated list.
func JoinFormats() string {
	names := make([]string, len(Formats))
	for i, f := range Formats {
		names[i] = string(f)
	}
	return strings.Join(names, ", ")
}

// Options control rendering. The zero value is valid and produces plain,
// uncolored, unabridged output — the right default for a file or a pipe.
type Options struct {
	// Color enables ANSI severity coloring. Callers should set it only when
	// the destination is an interactive terminal.
	Color bool

	// Limit caps how many findings [Table] prints, with a note about the
	// remainder. Zero prints all of them. It does not affect machine formats,
	// which must stay complete.
	Limit int
}

// Write renders doc to w in the given format.
//
// Renderers take a prepared [Document] rather than raw results so that
// deduplication happens exactly once, in [NewDocument], before any caller filters
// or ranks. When each renderer merged for itself, a caller that wanted to filter
// had no merged list to filter — and filtering the raw per-scanner results
// understates how many tools agreed. See scan.FilterBySeverity.
func Write(w io.Writer, format Format, doc Document, opts Options) error {
	switch format {
	case FormatTable:
		return Table(w, doc, opts)
	case FormatJSON:
		return JSON(w, doc)
	case FormatSARIF:
		return SARIF(w, doc)
	default:
		return fmt.Errorf("unknown format %q", format)
	}
}
