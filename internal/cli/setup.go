package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/AnimeshRy/pindrop/internal/scan"
	"github.com/AnimeshRy/pindrop/internal/toolinstall"
	"github.com/AnimeshRy/pindrop/internal/toolpath"
	"github.com/AnimeshRy/pindrop/internal/tui"
)

// setupOptions holds the flags for `pindrop setup`.
type setupOptions struct {
	yes   bool
	force bool
	only  []string
	dir   string
	check bool
	libc  string
}

func newSetupCommand(_ *globals) *cobra.Command {
	opts := &setupOptions{}

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Install the scanners Pindrop runs",
		Long: strings.TrimSpace(`
Install the scanners Pindrop runs.

Downloads a pinned release of each scanner for this machine, checks it against a
SHA-256 digest built into this copy of pindrop, and installs it into a directory
Pindrop manages. Nothing is written outside that directory, and no system package
manager is involved.

Already-installed scanners at the pinned version are skipped, so running this
again is cheap and makes no network requests.

The install directory is ~/.pindrop/bin. Set PINDROP_HOME to move it, or --dir to
install somewhere else entirely. It does not need to be on your PATH.`),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSetup(cmd.Context(), opts)
		},
	}

	f := cmd.Flags()
	f.BoolVarP(&opts.yes, "yes", "y", false,
		"skip the confirmation prompt")
	f.BoolVar(&opts.force, "force", false,
		"reinstall scanners that are already present, replacing any Pindrop did not install")
	f.StringSliceVar(&opts.only, "only", nil,
		"install only these scanners, by binary name")
	f.StringVar(&opts.dir, "dir", "",
		"install into this directory instead of the one Pindrop manages")
	f.BoolVar(&opts.check, "check", false,
		"report what is installed and exit; installs nothing")
	f.StringVar(&opts.libc, "libc", string(toolinstall.LibcAuto),
		"Linux C library to install for: auto, gnu, musl")

	cmd.RegisterFlagCompletionFunc("libc", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"auto", "gnu", "musl"}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.RegisterFlagCompletionFunc("only", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{"trivy", "osv-scanner", "opengrep", "trufflehog"}, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

func runSetup(ctx context.Context, opts *setupOptions) error {
	libc, err := toolinstall.ParseLibc(opts.libc)
	if err != nil {
		return err
	}

	manifest, err := toolinstall.Load()
	if err != nil {
		return err
	}

	if err := maybeAskSetupQuestions(opts, manifest); err != nil {
		return err
	}

	if err := validateOnly(manifest, opts.only); err != nil {
		return err
	}

	dir, home, err := setupDirs(opts.dir)
	if err != nil {
		return err
	}

	selected, unsupported := manifest.Select(opts.only, libc)
	if len(selected) == 0 {
		return unsupportedOnly(unsupported)
	}

	record := toolinstall.LoadRecord(home)

	if opts.check {
		return runCheck(ctx, selected, unsupported, dir, record)
	}
	return runInstall(ctx, selected, unsupported, dir, home, record, opts)
}

// maybeAskSetupQuestions runs a short first-run questionnaire on a terminal.
//
// It does not run when the user passed --yes, --check, or --dir, when
// PINDROP_HOME is set, or when settings already exist — a provisioned machine
// should not be re-interviewed on every setup.
func maybeAskSetupQuestions(opts *setupOptions, manifest *toolinstall.Manifest) error {
	if opts.yes || opts.check || opts.dir != "" {
		return nil
	}
	if os.Getenv(toolpath.HomeEnv) != "" {
		return nil
	}
	if toolpath.SettingsExist() {
		return nil
	}
	if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		return nil
	}

	return askSetupQuestions(opts, manifest)
}

func askSetupQuestions(opts *setupOptions, manifest *toolinstall.Manifest) error {
	defaultHome, err := toolpath.DefaultHome()
	if err != nil {
		return err
	}

	dirChoice, err := tui.AskDataDir(toolpath.Display(defaultHome))
	if err != nil {
		return err
	}
	if dirChoice.Cancelled {
		return errors.New("cancelled")
	}
	if !dirChoice.UseDefault {
		if err := saveSetupHome(dirChoice.CustomPath); err != nil {
			return err
		}
	}

	if len(opts.only) == 0 {
		names := manifest.Names()
		scannerOpts := make([]tui.ScannerOption, len(names))
		for i, name := range names {
			tool, _ := manifest.Tool(name)
			scannerOpts[i] = tui.ScannerOption{
				Name:    name,
				Version: tool.Version,
			}
		}

		choice, err := tui.AskScannerSelection(scannerOpts)
		if err != nil {
			return err
		}
		if choice.Cancelled {
			return errors.New("cancelled")
		}
		if !choice.InstallAll {
			opts.only = choice.Selected
		}
	}

	return nil
}

func saveSetupHome(path string) error {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("expanding ~ in %q: %w", path, err)
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	if err := toolpath.SaveHomeOverride(path); err != nil {
		return err
	}
	printf(os.Stderr, "Using %s for Pindrop data.\n", toolpath.Display(path))
	return nil
}

// readLine reads one line from in, without the trailing newline.
func readLine(in io.Reader) (string, error) {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading your answer: %w", err)
	}
	return strings.TrimSuffix(line, "\n"), nil
}

// setupDirs resolves the install directory and the home directory the install
// record lives in.
//
// With --dir the record still lives in Pindrop's own home, because the record is
// about what Pindrop installed, not about one directory.
func setupDirs(override string) (dir, home string, err error) {
	home, err = toolpath.Home()
	if err != nil {
		return "", "", err
	}

	if override == "" {
		dir, err = toolpath.Dir()
		return dir, home, err
	}

	dir, err = filepath.Abs(override)
	if err != nil {
		return "", "", fmt.Errorf("resolving --dir %q: %w", override, err)
	}
	return dir, home, nil
}

// validateOnly rejects an unknown --only value rather than silently installing
// nothing, which is what a typo would otherwise do.
func validateOnly(m *toolinstall.Manifest, only []string) error {
	for _, name := range only {
		if _, ok := m.Tool(name); !ok {
			return fmt.Errorf("unknown scanner %q in --only\n  Pindrop installs: %s",
				name, strings.Join(m.Names(), ", "))
		}
	}
	return nil
}

// unsupportedOnly reports that nothing can be installed here.
func unsupportedOnly(unsupported []error) error {
	if len(unsupported) == 0 {
		return errors.New("no scanners to install")
	}
	return fmt.Errorf("no scanner has a build for %s:\n%s",
		toolinstall.PlatformKey(), indentLines(errors.Join(unsupported...).Error()))
}

// runCheck reports what is installed without changing anything.
//
// It absorbs what would otherwise be a `pindrop doctor`: which copy of each tool
// Pindrop resolves, where that copy came from, and whether it actually runs. The
// origin column is the one that explains the confusing case — a user who
// installed a scanner through setup but has an older one earlier on PATH.
func runCheck(ctx context.Context, selected []toolinstall.Selected,
	unsupported []error, dir string, record *toolinstall.Record,
) error {
	out := os.Stdout
	printf(out, "Pindrop installs scanners into %s\n\n", toolpath.Display(dir))

	var missing []string
	for _, sel := range selected {
		state := toolinstall.Status(sel, dir, record)
		if state == toolinstall.StateMissing {
			missing = append(missing, sel.Tool.Name)
		}

		resolved, origin, err := toolpath.LookupOrigin(sel.Tool.Name, toolpath.Env(sel.Tool.Name))
		where := "not found"
		if err == nil {
			where = fmt.Sprintf("%s (%s)", toolpath.Display(resolved), origin)
		}

		printf(out, "  %-13s %-9s %-10s %s\n",
			sel.Tool.Name, sel.Tool.Version, state, where)
	}

	for _, err := range unsupported {
		printf(out, "\n%s\n", indentLines(err.Error()))
	}

	// Preflight is the real verification: it runs each tool, so it catches a
	// present-but-broken binary and Trivy's version floor, neither of which a
	// stored digest can tell us anything about.
	printf(out, "\n")
	scanners := scannerRegistry(&scanOptions{scanners: nil})
	usable, unavailable := scan.Usable(ctx, scanners)
	printf(out, "%d of %d scanners are ready to run.\n", len(usable), len(scanners))
	if unavailable != nil {
		printf(out, "\n%s\n", indentLines(unavailable.Error()))
	}

	if len(missing) > 0 {
		return fmt.Errorf("not installed: %s\n  Run `pindrop setup` to install them",
			strings.Join(missing, ", "))
	}
	return nil
}

// plan is what an install run intends to do.
type plan struct {
	// todo needs downloading.
	todo []toolinstall.Selected
	// skipped is already installed at the pinned version.
	skipped []string
	// foreign is present but installed by somebody other than Pindrop.
	foreign []string
}

// classify sorts selected into a [plan].
//
// Done before anything is downloaded so the prompt can state exactly what is
// about to happen, and so an already-provisioned machine finishes without a
// single network request — which is the whole of the offline story.
func classify(selected []toolinstall.Selected, dir string,
	record *toolinstall.Record, force bool,
) plan {
	var p plan
	for _, sel := range selected {
		state := toolinstall.Status(sel, dir, record)

		// --force overrides both of the "leave it alone" states.
		if force && (state == toolinstall.StateInstalled || state == toolinstall.StateForeign) {
			p.todo = append(p.todo, sel)
			continue
		}

		switch state {
		case toolinstall.StateInstalled:
			p.skipped = append(p.skipped, sel.Tool.Name)
		case toolinstall.StateForeign:
			p.foreign = append(p.foreign, sel.Tool.Name)
		default:
			p.todo = append(p.todo, sel)
		}
	}
	return p
}

// runInstall downloads and installs everything that is missing or outdated.
func runInstall(ctx context.Context, selected []toolinstall.Selected,
	unsupported []error, dir, home string, record *toolinstall.Record, opts *setupOptions,
) error {
	p := classify(selected, dir, record, opts.force)
	todo, skipped, foreign := p.todo, p.skipped, p.foreign

	for _, err := range unsupported {
		printf(os.Stderr, "%s\n\n", indentLines(err.Error()))
	}

	if len(foreign) > 0 {
		// Never silently replace a binary Pindrop did not put there. `pindrop
		// setup --dir /usr/local/bin` must not clobber a user's Homebrew Trivy.
		fmt.Fprintf(os.Stderr,
			"Already present but not installed by Pindrop, so left alone: %s\n"+
				"  Pindrop will still use them. Use --force to replace them with pinned builds.\n\n",
			strings.Join(foreign, ", "))
	}

	if len(todo) == 0 {
		printf(os.Stdout, "All %d scanners are already installed in %s.\n",
			len(skipped)+len(foreign), toolpath.Display(dir))
		printNextSteps(os.Stdout)
		return nil
	}

	if !opts.yes {
		ok, err := confirmInstall(os.Stdin, os.Stdout, todo, dir)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled")
		}
	}

	toolinstall.CleanTemp(dir)

	installOpts := toolinstall.Options{Dir: dir, Force: opts.force}
	var failed []string

	live := isTerminal(os.Stdout)

	for _, sel := range todo {
		printf(os.Stdout, "  %-13s %-9s ", sel.Tool.Name, sel.Tool.Version)

		if err := toolinstall.Install(ctx, sel, installOpts, downloadMeter(live, sel)); err != nil {
			if ctx.Err() != nil {
				printf(os.Stdout, "\r  %-13s %-9s cancelled          \n",
					sel.Tool.Name, sel.Tool.Version)
				return ctx.Err()
			}
			printf(os.Stdout, "\r  %-13s %-9s failed             \n",
				sel.Tool.Name, sel.Tool.Version)
			printf(os.Stderr, "\n%s\n\n", indentLines(err.Error()))
			failed = append(failed, sel.Tool.Name)
			record.Forget(sel.Tool.Name)
			continue
		}

		record.Set(sel.Tool.Name, sel.Tool.Version, sel.Asset.SHA256)
		printf(os.Stdout, "\r  %-13s %-9s installed          \n",
			sel.Tool.Name, sel.Tool.Version)
	}

	// Saved even on partial failure, so a retry skips what already succeeded.
	if err := record.Save(home); err != nil {
		printf(os.Stderr, "warning: %v\n", err)
	}

	if len(failed) > 0 {
		return fmt.Errorf("%d of %d scanners failed to install: %s",
			len(failed), len(todo), strings.Join(failed, ", "))
	}

	printf(os.Stdout, "\nSetup complete. %d scanners installed in %s\n",
		len(todo), toolpath.Display(dir))
	printNextSteps(os.Stdout)
	return nil
}

// printNextSteps tells the user what they can now do. This is the line the whole
// command exists to earn.
func printNextSteps(w io.Writer) {
	printf(w, "You do not need to add that directory to your PATH — "+
		"pindrop finds these itself.\n\nScan a repository:\n  pindrop scan /path/to/repo\n")
}

// confirmInstall shows what is about to be downloaded and asks permission.
//
// Naming the hosts and the total size before fetching third-party executables is
// the disclosure a security tool owes its user: "it downloaded 200 MB from
// somewhere" is not something anyone should discover afterwards.
func confirmInstall(in io.Reader, out io.Writer, todo []toolinstall.Selected,
	dir string,
) (bool, error) {
	var total int64
	for _, sel := range todo {
		total += sel.Asset.Size
	}

	summary := fmt.Sprintf("pindrop will download %d scanner%s into %s (%s):",
		len(todo), plural(len(todo)), toolpath.Display(dir), humanBytes(total))

	var details strings.Builder
	for _, sel := range todo {
		fmt.Fprintf(&details, "  %-13s %-9s %8s   github.com/%s\n",
			sel.Tool.Name, sel.Tool.Version, humanBytes(sel.Asset.Size), sel.Tool.Repo)
	}
	details.WriteString("\nEach download is verified against a SHA-256 digest committed in this build.")

	// A non-interactive stdin must not be read: a CI job that blocks forever on a
	// prompt nobody can answer is a worse failure than an error telling it to pass
	// --yes.
	if !isTerminal(os.Stdin) {
		return false, errors.New(
			"stdin is not a terminal, so there is nobody to confirm with\n" +
				"  Re-run with --yes to install without confirmation")
	}

	_ = in
	_ = out

	result, err := tui.AskInstallConfirm(summary, details.String())
	if err != nil {
		return false, err
	}
	if result.Confirmed {
		fmt.Fprintln(os.Stderr)
	}
	return result.Confirmed, nil
}

// printf writes to w, discarding the error.
//
// A failed write to a terminal is not something the user can act on, and there is
// nothing left to report it with. The rest of the CLI writes to os.Stderr the same
// way; this exists because these functions take an io.Writer so they can be
// exercised without a terminal.
func printf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// humanBytes renders a byte count in the units a download is discussed in.
func humanBytes(n int64) string {
	const mb = 1 << 20
	if n < mb {
		return fmt.Sprintf("%d KB", n/1024)
	}
	return fmt.Sprintf("%d MB", n/mb)
}

// plural returns the plural suffix for n.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// offerInstall asks whether to install the scanners that are missing, and does so
// if the user agrees. It reports whether anything was installed.
//
// Only on a terminal. Three guards, each closing a different failure:
//
//   - stdin must be a terminal, or the read blocks forever on a prompt nobody can
//     answer. A CI job hanging is worse than a CI job scanning with three tools.
//   - stderr must be a terminal, or the prompt is written into a log file where
//     it reads as noise.
//   - only a *missing* tool is offered. A scanner that is installed but broken, or
//     too old, is not something reinstalling silently fixes, and pretending
//     otherwise would hide a real problem.
//
// Declining is not an error: the scan continues with whatever is available, which
// is the standing rule that a missing scanner reduces coverage rather than
// failing the run.
func offerInstall(ctx context.Context, unavailable error, overridden map[string]bool) (bool, error) {
	if !isTerminal(os.Stdin) || !isTerminal(os.Stderr) {
		return false, nil
	}

	manifest, err := toolinstall.Load()
	if err != nil {
		// Nothing is installable, so there is nothing to offer. Fall through to
		// the usual warning rather than turning a scan into a setup failure.
		//nolint:nilerr // an unusable manifest means no offer, not an error
		return false, nil
	}

	missing := missingInstallable(manifest, unavailable, overridden)
	if len(missing) == 0 {
		return false, nil
	}

	dir, home, err := setupDirs("")
	if err != nil {
		// Same reasoning: no home directory means no offer, not a failed scan.
		//nolint:nilerr // cannot offer an install without somewhere to install to
		return false, nil
	}

	selected, _ := manifest.Select(missing, toolinstall.LibcAuto)
	if len(selected) == 0 {
		return false, nil
	}

	var total int64
	for _, sel := range selected {
		total += sel.Asset.Size
	}

	fmt.Fprintln(os.Stderr)
	prompt := fmt.Sprintf("%d of %d scanners are not installed: %s\nInstall them now into %s (%s, checksum-verified)?",
		len(missing), len(manifest.Names()), strings.Join(missing, ", "),
		toolpath.Display(dir), humanBytes(total))

	agreed, err := tui.AskInstallOffer(prompt)
	if err != nil {
		return false, err
	}
	if !agreed {
		printf(os.Stderr, "\nSkipping. Run `pindrop setup` when you want them.\n\n")
		return false, nil
	}

	return installNow(ctx, selected, dir, home)
}

// readYesNo reads a [Y/n] answer, defaulting to yes on an empty line.
func readYesNo(in io.Reader) (bool, error) {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("reading your answer: %w", err)
	}

	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// installNow installs selected, reporting progress to stderr.
//
// Writes to stderr rather than stdout because this runs inside `pindrop scan`,
// whose stdout is the report.
func installNow(ctx context.Context, selected []toolinstall.Selected, dir, home string) (bool, error) {
	printf(os.Stderr, "\n")
	record := toolinstall.LoadRecord(home)
	toolinstall.CleanTemp(dir)

	var installed bool
	for _, sel := range selected {
		printf(os.Stderr, "  %-13s %-9s ", sel.Tool.Name, sel.Tool.Version)

		if err := toolinstall.Install(ctx, sel, toolinstall.Options{Dir: dir}, nil); err != nil {
			if ctx.Err() != nil {
				return installed, ctx.Err()
			}
			printf(os.Stderr, "failed\n%s\n", indentLines(err.Error()))
			continue
		}

		record.Set(sel.Tool.Name, sel.Tool.Version, sel.Asset.SHA256)
		printf(os.Stderr, "installed\n")
		installed = true
	}

	if installed {
		if err := record.Save(home); err != nil {
			printf(os.Stderr, "warning: %v\n", err)
		}
	}
	printf(os.Stderr, "\n")
	return installed, nil
}

// missingInstallable returns the binaries that are both absent and installable.
//
// The unavailability error names scanners, not binaries — the OSV adapter reports
// "osv" while its executable is "osv-scanner" — so the match is by scanner name
// mapped onto the manifest's binary names. A scanner that is present but broken,
// or too old, never appears here: its Preflight error is not a not-found error,
// and reinstalling would not fix it.
func missingInstallable(m *toolinstall.Manifest, unavailable error, overridden map[string]bool) []string {
	byBinary := map[string]*scan.UnavailableError{}
	for _, u := range unavailableScanners(unavailable) {
		byBinary[scannerBinary(u.Scanner)] = u
	}

	var out []string
	for _, name := range m.Names() {
		// An explicit --<tool>-binary path is not something installing fixes: the
		// scan would keep looking at the path the user gave.
		if overridden[name] {
			continue
		}
		if u, ok := byBinary[name]; ok && strings.Contains(u.Reason, "not found") {
			out = append(out, name)
		}
	}
	return out
}

// scannerBinary maps a scanner's name to its executable's name. They differ for
// exactly one adapter, which is why this is not the identity function.
func scannerBinary(scanner string) string {
	if scanner == "osv" {
		return "osv-scanner"
	}
	return scanner
}

// unavailableScanners collects every [scan.UnavailableError] in a joined error.
//
// It walks the join tree but does not descend *through* an UnavailableError, even
// though that type also unwraps to several errors. Recursing into it yields its
// causes — ErrUnavailable and the underlying exec error — and loses the node
// itself, which is the one carrying the scanner name and reason. That mistake
// silently produced an empty result and no install offer at all.
func unavailableScanners(err error) []*scan.UnavailableError {
	if err == nil {
		return nil
	}

	// A deliberate type assertion rather than errors.As: As would search *through*
	// this node into its causes, which is the very over-reach this function exists
	// to avoid. Here the question is "is this node one", not "does this tree
	// contain one".
	//
	//nolint:errorlint // identity of this node, not a search of its causes
	if u, ok := err.(*scan.UnavailableError); ok {
		return []*scan.UnavailableError{u}
	}

	//nolint:errorlint // walking the tree structurally, not matching a target
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		//nolint:errorlint // same
		if wrapped, ok := err.(interface{ Unwrap() error }); ok {
			return unavailableScanners(wrapped.Unwrap())
		}
		return nil
	}

	var out []*scan.UnavailableError
	for _, e := range joined.Unwrap() {
		out = append(out, unavailableScanners(e)...)
	}
	return out
}

// downloadMeter returns a progress callback that overwrites a percentage in place.
//
// Deliberately a carriage return rather than a second bubbletea model: setup
// writes a line per tool and only needs the current one to stop looking frozen
// while 70 MB arrives. Returns nil when stdout is not a terminal, so a redirected
// install log gains one line per tool instead of thousands of partial ones.
func downloadMeter(live bool, sel toolinstall.Selected) func(done, total int64) {
	if !live {
		return nil
	}

	var lastPercent int64 = -1
	return func(done, total int64) {
		if total <= 0 {
			return
		}
		// Only repaint on a whole-percent change: the callback fires once per
		// read, which is thousands of times for a 70 MB asset.
		percent := done * 100 / total
		if percent == lastPercent {
			return
		}
		lastPercent = percent

		// Repaint the whole row, not just the number: a bare carriage return
		// would overwrite the tool name that was printed before the download
		// started.
		status := fmt.Sprintf("downloading %3d%%", percent)
		if percent == 100 {
			status = "verifying…      "
		}
		printf(os.Stdout, "\r  %-13s %-9s %s", sel.Tool.Name, sel.Tool.Version, status)
	}
}
