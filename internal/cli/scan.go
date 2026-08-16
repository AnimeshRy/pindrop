package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/report"
	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/scan/opengrep"
	"github.com/AnimeshRy/pindrop/internal/scan/osv"
	"github.com/AnimeshRy/pindrop/internal/scan/trivy"
	"github.com/AnimeshRy/pindrop/internal/scan/trufflehog"
	"github.com/AnimeshRy/pindrop/internal/tui"
)

// defaultTableLimit caps the terminal table by default.
//
// This is the product thesis expressed as a constant: a wall of two thousand
// findings is worth the same as none. The full set is always one flag away, and
// machine formats are never truncated.
const defaultTableLimit = 25

// scanOptions holds the flags for `pindrop scan`.
type scanOptions struct {
	format         string
	out            string
	scanners       []string
	minSeverity    string
	limit          int
	failOn         string
	trivyBinary    string
	osvBinary      string
	opengrepBinary string
	opengrepRules  []string
	cacheDir       string
	callAnalysis   bool

	trufflehogBinary       string
	trufflehogExcludePaths []string
	verifySecrets          bool

	exclude           []string
	noDefaultExcludes bool
	configPath        string

	noHistory bool
	diff      bool

	progress  string
	noInstall bool
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
	f.StringVar(&opts.opengrepBinary, "opengrep-binary", "opengrep",
		"path to the Opengrep executable")
	f.StringSliceVar(&opts.opengrepRules, "opengrep-rules", nil,
		"rule file, directory, or registry name to use instead of the bundled ruleset")
	f.StringVar(&opts.trufflehogBinary, "trufflehog-binary", "trufflehog",
		"path to the TruffleHog executable")
	f.StringSliceVar(&opts.trufflehogExcludePaths, "trufflehog-exclude-paths", nil,
		"additional path regexes for TruffleHog to skip, on top of the built-in set")
	// This flag is the last point of disclosure before the user's own credentials
	// leave the machine, so the help text says so rather than describing the
	// feature. See docs/decisions/0008-trufflehog-verification-opt-in.md.
	f.BoolVar(&opts.verifySecrets, "verify-secrets", false,
		"ask each provider whether a discovered secret is live; SENDS the secrets "+
			"it finds to third-party APIs")
	f.BoolVar(&opts.callAnalysis, "call-analysis", false,
		"enable OSV-Scanner reachability analysis (slower; compiles the target)")
	f.StringVar(&opts.cacheDir, "cache-dir", "",
		"directory for scanner caches, such as the vulnerability database")
	f.BoolVar(&opts.noHistory, "no-history", false,
		"do not record this scan in ~/.pindrop/pindrop.db")
	f.BoolVar(&opts.diff, "diff", false,
		"show only what changed since the previous scan of this repository")
	f.StringSliceVar(&opts.exclude, "exclude", nil,
		"skip a directory or file, repeatable (prefix with dir: or file: to be explicit)")
	f.BoolVar(&opts.noDefaultExcludes, "no-default-excludes", false,
		"do not apply the built-in exclusions (node_modules, .venv, build output, ...)")
	f.StringVar(&opts.configPath, "config", "",
		"path to a config file (default: "+ConfigName+" in the scanned directory)")
	f.StringVar(&opts.progress, "progress", "auto",
		"progress display: auto, animated, plain, none")
	f.BoolVar(&opts.noInstall, "no-install", false,
		"never offer to install missing scanners, even on a terminal")

	registerFlagCompletion(cmd, "format", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"table", "json", "sarif", "csv", "markdown"}, cobra.ShellCompDirectiveNoFileComp
	})
	registerFlagCompletion(cmd, "min-severity", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"info", "low", "medium", "high", "critical"}, cobra.ShellCompDirectiveNoFileComp
	})
	registerFlagCompletion(cmd, "fail-on", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"info", "low", "medium", "high", "critical"}, cobra.ShellCompDirectiveNoFileComp
	})
	registerFlagCompletion(cmd, "progress", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return tui.ModeNames, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

// scannerRegistry constructs every scanner Pindrop knows about, configured by
// opts.
//
// This is the composition root's composition root: adapters are wired here and
// nowhere else, because internal/scan must not import them or the dependency
// becomes a cycle. Adding a scanner touches exactly two places — its new
// subpackage and this slice.
//
// It is a function rather than an inline literal so that `pindrop setup --check`
// can preflight the same registry a scan would build. A bespoke --version check
// there could pass while a real scan failed.
func scannerRegistry(opts *scanOptions) []scan.Scanner {
	return []scan.Scanner{
		trivy.New(
			trivy.WithBinary(opts.trivyBinary),
			trivy.WithScanners(opts.scanners...),
			trivy.WithCacheDir(opts.cacheDir),
		),
		osv.New(
			osv.WithBinary(opts.osvBinary),
			osv.WithCallAnalysis(opts.callAnalysis),
		),
		opengrep.New(
			opengrep.WithBinary(opts.opengrepBinary),
			opengrep.WithRules(opts.opengrepRules...),
		),
		trufflehog.New(
			trufflehog.WithBinary(opts.trufflehogBinary),
			trufflehog.WithVerification(opts.verifySecrets),
			trufflehog.WithExcludePaths(opts.trufflehogExcludePaths...),
		),
	}
}

// scanRequest is a validated `pindrop scan` invocation.
type scanRequest struct {
	format      report.Format
	minSeverity scan.Severity
	failOn      scan.Severity
	target      scan.Target
}

// parseScanOptions validates every flag before anything expensive happens.
//
// Grouped so that a mistyped --format fails before a scanner is preflighted,
// rather than after a minute of scanning.
func parseScanOptions(opts *scanOptions, path string) (scanRequest, error) {
	var r scanRequest
	var err error

	if r.format, err = report.ParseFormat(opts.format); err != nil {
		return r, err
	}
	if r.minSeverity, err = parseOptionalSeverity(opts.minSeverity, "--min-severity"); err != nil {
		return r, err
	}
	if r.failOn, err = parseOptionalSeverity(opts.failOn, "--fail-on"); err != nil {
		return r, err
	}
	if err = tui.ValidateMode(opts.progress); err != nil {
		return r, err
	}
	if r.target, err = resolveTarget(path); err != nil {
		return r, err
	}

	// A malformed config is fatal here rather than a warning, and before any
	// scanner is preflighted. A security tool that silently ignores its own
	// configuration is worse than one that refuses to start: the user believes
	// the exclusions applied.
	cfg, err := loadConfig(r.target.Path, opts.configPath)
	if err != nil {
		return r, err
	}
	if r.target.Excludes, err = resolveExcludes(cfg, opts.exclude, opts.noDefaultExcludes); err != nil {
		return r, err
	}
	return r, nil
}

func runScan(ctx context.Context, g *globals, opts *scanOptions, path string) error {
	req, err := parseScanOptions(opts, path)
	if err != nil {
		return err
	}
	format, minSeverity, failOn, target := req.format, req.minSeverity, req.failOn, req.target

	scanners := scannerRegistry(opts)

	// Preflight before scanning so a missing tool is reported as setup guidance
	// rather than as a mid-scan failure.
	//
	// A missing optional scanner reduces coverage; it does not abort the scan.
	// Requiring every tool to be installed would break `pindrop scan .` on a
	// machine that has only Trivy, which is the zero-setup first run the product
	// depends on. Only having nothing left to run is fatal.
	usable, unavailable, err := resolveScanners(ctx, scanners, opts)
	if err != nil {
		return err
	}

	mode := tui.ResolveMode(opts.progress, isTerminal(os.Stderr), os.Getenv("TERM"), g.logLevel)

	// The skipped block is text above the display in plain mode, and dimmed rows
	// inside it when animated — printing both would say the same thing twice.
	if unavailable != nil && mode != tui.ModeAnimated {
		fmt.Fprintf(os.Stderr, "Skipping unavailable scanners:\n%s\n"+
			"  Run `pindrop setup` to install the missing ones.\n\n",
			indentLines(unavailable.Error()))
	}

	slog.Debug("starting scan", "path", target.Path, "scanners", len(scanners))
	started := time.Now()

	progress := tui.StartScan(target.Path, tui.Options{
		Mode:  mode,
		Color: g.colorFor(os.Stderr),
	})
	// Safety net; the success path stops it explicitly before writing to stdout.
	defer progress.Stop()

	// Replayed into the display so unavailable scanners appear as dimmed rows
	// rather than as a wall of text the user has to reconcile with the rows.
	if mode == tui.ModeAnimated && unavailable != nil {
		replaySkipped(scanners, usable, progress)
	}

	results, scanErr := scan.Run(ctx, usable, target, scan.WithObserver(progress))

	// The display must be finished and the cursor restored before the report is
	// written, or a frame can interleave with the table on stdout.
	progress.Stop()
	if len(results) == 0 && scanErr != nil {
		return scanErr
	}
	// A partial failure must not discard the findings we did collect.
	if scanErr != nil {
		slog.Warn("some scanners failed", "error", scanErr)
	}

	// Persist BEFORE filtering, and from the unfiltered set.
	//
	// --min-severity and --scanners narrow what the user is shown, not what was
	// true. Recording the narrowed set would make the next default scan report
	// every dropped finding as newly reintroduced, and `--scanners vuln` would
	// record a run in which every secret and code finding had vanished.
	if !opts.noHistory {
		recordHistory(ctx, results, target, usable, started)
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

// replaySkipped reports the unavailable scanners into the display.
//
// Their absence is known before the display exists, because the install offer has
// to happen first — a prompt and an animation cannot share stderr. Rather than
// preflighting a third time, the skipped set is derived by diffing the registry
// against what survived.
//
// The indices deliberately start after the usable set rather than reusing the
// registry's. scan.Run reports on `usable`, which is re-indexed from zero, so a
// skipped scanner sitting at its registry index would be overwritten by whichever
// usable scanner happens to land on the same row — which is exactly what happened
// the first time this was wired up. Placing them last also reads better: the tools
// that ran, then the ones that could not.
func replaySkipped(scanners, usable []scan.Scanner, obs scan.Observer) {
	live := make(map[string]bool, len(usable))
	for _, s := range usable {
		live[s.Name()] = true
	}

	next := len(usable)
	for _, s := range scanners {
		if !live[s.Name()] {
			obs.Observe(scan.Event{Scanner: s.Name(), Index: next, Phase: scan.PhaseSkipped})
			next++
		}
	}
}

// resolveScanners preflights the registry, offering to install what is missing.
//
// The offer happens here rather than inside the display, because a prompt and an
// animation cannot share stderr. Declining is not an error — the scan proceeds
// with whatever is available, which is the standing rule that a missing scanner
// reduces coverage rather than failing the run. Only an empty usable set is fatal.
func resolveScanners(ctx context.Context, scanners []scan.Scanner, opts *scanOptions) (
	usable []scan.Scanner, unavailable error, err error,
) {
	usable, unavailable = scan.Usable(ctx, scanners)

	if unavailable != nil && !opts.noInstall {
		installed, err := offerInstall(ctx, unavailable, opts.overriddenBinaries())
		if err != nil {
			return nil, nil, err
		}
		if installed {
			usable, unavailable = scan.Usable(ctx, scanners)
		}
	}

	if len(usable) == 0 {
		return nil, nil, fmt.Errorf(
			"no scanners are installed, so there is nothing to scan with\n\n%s\n\n"+
				"Run `pindrop setup` to install them",
			indentLines(unavailable.Error()))
	}
	return usable, unavailable, nil
}

// overriddenBinaries names the tools whose executable the user pointed at
// explicitly.
//
// Offering to install one of these would be a lie: `pindrop setup` writes to the
// managed directory, and a scan told to use /opt/trivy will keep looking there.
// The right answer for an override that does not resolve is the existing error,
// which names the path they gave.
func (o *scanOptions) overriddenBinaries() map[string]bool {
	overridden := map[string]bool{}
	for _, b := range []struct{ value, def, binary string }{
		{o.trivyBinary, "trivy", "trivy"},
		{o.osvBinary, "osv-scanner", "osv-scanner"},
		{o.opengrepBinary, "opengrep", "opengrep"},
		{o.trufflehogBinary, "trufflehog", "trufflehog"},
	} {
		if b.value != b.def {
			overridden[b.binary] = true
		}
	}
	return overridden
}
