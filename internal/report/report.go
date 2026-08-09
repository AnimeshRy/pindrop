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

	"github.com/AnimeshRy/pindrop/internal/scan"
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

// Write renders results to w in the given format.
//
// It assembles the [Document] itself; callers that need control over how the
// document was built should use [WriteDocument] instead.
func Write(w io.Writer, format Format, results []scan.Result, opts Options) error {
	switch format {
	case FormatTable:
		return Table(w, results, opts)
	case FormatJSON:
		return JSON(w, results)
	case FormatSARIF:
		return SARIF(w, results)
	default:
		return fmt.Errorf("unknown format %q", format)
	}
}

// WriteDocument renders a prebuilt Document, for callers that need to control
// how it was assembled — persisting the unfiltered set while displaying a
// filtered one, or re-rendering a document loaded from scan history.
//
// Rendering is driven entirely by the document's own [Document.Findings] and
// [Document.Scans], in the order they appear: a caller that filtered or
// reordered them meant it, and re-deriving anything here would quietly undo
// the control this function exists to give.
func WriteDocument(w io.Writer, format Format, doc Document, opts Options) error {
	switch format {
	case FormatTable:
		return renderTable(w, doc.Findings, doc.Scans, opts)
	case FormatJSON:
		return encodeDocument(w, doc)
	case FormatSARIF:
		return renderSARIF(w, doc.Findings)
	default:
		return fmt.Errorf("unknown format %q", format)
	}
}
