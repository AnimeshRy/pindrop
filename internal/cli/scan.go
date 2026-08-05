package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/scan/osv"
	"github.com/AnimeshRy/pindrop/internal/scan/trivy"
)

// defaultTableLimit caps the terminal table by default.
//
// This is the product thesis expressed as a constant: a wall of two thousand
// findings is worth the same as none. The full set is always one flag away, and
// machine formats are never truncated.
const defaultTableLimit = 25

// scanOptions holds the flags for `pindrop scan`.
type scanOptions struct {
	format       string
	out          string
	scanners     []string
	minSeverity  string
	limit        int
	failOn       string
	trivyBinary  string
	osvBinary    string
	cacheDir     string
	callAnalysis bool
}

func newScanCommand(g *globals) *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a directory for security findings",
		Long: strings.TrimSpace(`
Scan a directory for security findings.

Runs every configured scanner in parallel, normalizes their output into a single
ranked list, and writes it in the requested format. Defaults to the current
directory.`),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			return runScan(cmd.Context(), g, opts, path)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&opts.format, "format", "f", string(report.FormatTable),
		"output format: "+report.JoinFormats())
	f.StringVarP(&opts.out, "out", "o", "",
		"write the report to a file instead of stdout")
	f.StringSliceVar(&opts.scanners, "scanners", trivy.DefaultScanners,
		"Trivy sub-scanners to run: vuln, misconfig, secret, license")
	f.StringVar(&opts.minSeverity, "min-severity", "",
		"drop findings below this severity: info, low, medium, high, critical")
	f.IntVar(&opts.limit, "limit", defaultTableLimit,
		"max rows in table output; 0 shows all")
	f.StringVar(&opts.failOn, "fail-on", "",
		"exit non-zero if any finding is at or above this severity")
	f.StringVar(&opts.trivyBinary, "trivy-binary", "trivy",
		"path to the Trivy executable")
	f.StringVar(&opts.osvBinary, "osv-binary", "osv-scanner",
		"path to the OSV-Scanner executable")
	f.BoolVar(&opts.callAnalysis, "call-analysis", false,
		"enable OSV-Scanner reachability analysis (slower; compiles the target)")
	f.StringVar(&opts.cacheDir, "cache-dir", "",
		"directory for scanner caches, such as the vulnerability database")

	return cmd
}

func runScan(ctx context.Context, g *globals, opts *scanOptions, path string) error {
	format, err := report.ParseFormat(opts.format)
	if err != nil {
		return err
	}

	minSeverity, err := parseOptionalSeverity(opts.minSeverity, "--min-severity")
	if err != nil {
		return err
	}
	failOn, err := parseOptionalSeverity(opts.failOn, "--fail-on")
	if err != nil {
		return err
	}

	target, err := resolveTarget(path)
	if err != nil {
		return err
	}

	// The scanner registry. Adapters are wired here and nowhere else: internal/scan
	// must not import them, or the dependency becomes a cycle.
	scanners := []scan.Scanner{
		trivy.New(
			trivy.WithBinary(opts.trivyBinary),
			trivy.WithScanners(opts.scanners...),
			trivy.WithCacheDir(opts.cacheDir),
		),
		osv.New(
			osv.WithBinary(opts.osvBinary),
			osv.WithCallAnalysis(opts.callAnalysis),
		),
	}

	// Preflight before scanning so a missing tool is reported as setup guidance
	// rather than as a mid-scan failure.
	//
	// A missing optional scanner reduces coverage; it does not abort the scan.
	// Requiring every tool to be installed would break `pindrop scan .` on a
	// machine that has only Trivy, which is the zero-setup first run the product
	// depends on. Only having nothing left to run is fatal.
	usable, unavailable := scan.Usable(ctx, scanners)
	if len(usable) == 0 {
		return unavailable
	}
	if unavailable != nil {
		fmt.Fprintf(os.Stderr, "Skipping unavailable scanners:\n%s\n\n", indentLines(unavailable.Error()))
	}
	scanners = usable

	slog.Debug("starting scan", "path", target.Path, "scanners", len(scanners))

	results, scanErr := scan.Run(ctx, scanners, target)
	if len(results) == 0 && scanErr != nil {
		return scanErr
	}
	// A partial failure must not discard the findings we did collect.
	if scanErr != nil {
		slog.Warn("some scanners failed", "error", scanErr)
	}

	if minSeverity != "" {
		results = filterBySeverity(results, minSeverity)
	}

	if err := writeReport(results, format, opts, g); err != nil {
		return err
	}

	if failOn != "" {
		if worst, ok := exceedsThreshold(results, failOn); ok {
			return fmt.Errorf("found %s findings at or above --fail-on=%s", worst, failOn)
		}
	}
	return nil
}

// writeReport renders results to the configured destination.
func writeReport(results []scan.Result, format report.Format, opts *scanOptions, g *globals) error {
	renderOpts := report.Options{
		Color: g.color(),
		Limit: opts.limit,
	}

	if opts.out == "" {
		return report.Write(os.Stdout, format, results, renderOpts)
	}

	// A report written to a file is read later by a machine or a different
	// terminal, so it must never carry ANSI escapes or be truncated.
	renderOpts.Color = false
	renderOpts.Limit = 0

	if dir := filepath.Dir(opts.out); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}

	f, err := os.Create(opts.out)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	// Safety net for the error paths below; the success path closes explicitly
	// so that a failed flush is reported rather than swallowed.
	defer func() { _ = f.Close() }()

	if err := report.Write(f, format, results, renderOpts); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing output file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "wrote %s report to %s\n", format, opts.out)
	return nil
}

// indentLines indents every line of s by two spaces, so a multi-scanner
// unavailability report reads as a list under its heading rather than running
// flush against the left margin.
func indentLines(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = "  " + line
	}
	return strings.Join(lines, "\n")
}

// resolveTarget validates the scan path and makes it absolute.
func resolveTarget(path string) (scan.Target, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return scan.Target{}, fmt.Errorf("resolving %q: %w", path, err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return scan.Target{}, fmt.Errorf("path does not exist: %s", path)
		}
		return scan.Target{}, fmt.Errorf("reading %q: %w", path, err)
	}
	if !info.IsDir() {
		return scan.Target{}, fmt.Errorf("path is not a directory: %s", path)
	}

	return scan.Target{Path: abs}, nil
}

// parseOptionalSeverity parses a severity flag, treating empty as unset.
func parseOptionalSeverity(value, flagName string) (scan.Severity, error) {
	if value == "" {
		return "", nil
	}
	sev, err := scan.ParseSeverity(value)
	if err != nil {
		return "", fmt.Errorf("invalid %s: %w", flagName, err)
	}
	return sev, nil
}

// filterBySeverity drops findings ranked below min.
func filterBySeverity(results []scan.Result, min scan.Severity) []scan.Result {
	filtered := make([]scan.Result, 0, len(results))
	for _, r := range results {
		kept := make([]scan.Finding, 0, len(r.Findings))
		for _, f := range r.Findings {
			if f.Severity.Rank() >= min.Rank() {
				kept = append(kept, f)
			}
		}
		r.Findings = kept
		filtered = append(filtered, r)
	}
	return filtered
}

// exceedsThreshold reports the most severe finding at or above threshold.
func exceedsThreshold(results []scan.Result, threshold scan.Severity) (scan.Severity, bool) {
	worst, found := scan.SeverityUnknown, false
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Severity.Rank() >= threshold.Rank() && f.Severity.Rank() >= worst.Rank() {
				worst, found = f.Severity, true
			}
		}
	}
	return worst, found
}
