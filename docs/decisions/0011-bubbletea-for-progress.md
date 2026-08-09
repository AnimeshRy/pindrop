# 0011 — bubbletea and lipgloss for the live scan display

**Status:** accepted
**Date:** 2026-08-09

## Context

`pindrop scan` was silent between preflight and the final table. That is not a
cosmetic gap. Every adapter buffers its child's stdout *and* stderr into a
`bytes.Buffer`, and OSV-Scanner is run with `--verbosity error`, so the tools'
own progress output is deliberately suppressed. Each adapter has a ten-minute
timeout. On a large repository the product looked hung for minutes, which for a
first-time user is indistinguishable from broken.

The obvious fix — print a line as each scanner finishes — is worse than it
sounds, because `scan.Run` fans all four out concurrently. The last one to finish
determines the wall clock, so a naive log tells you nothing until it is nearly
over.

Against that sits `docs/development/conventions.md`: *"Prefer stdlib. Every
dependency in a security tool is supply-chain surface."* Before this change the
module had exactly one direct dependency, cobra.

## Decision

Adopt **bubbletea** and **lipgloss**, confined to a single package,
`internal/tui`.

The dependency count goes from 3 modules to 33. That is the real cost and it
should not be understated in a tool whose pitch includes supply-chain hygiene.
Three things make it acceptable:

**The imports are confined to one leaf package.** Nothing outside `internal/tui`
imports either library. `internal/scan` reports progress through an interface it
defines itself — `scan.Observer`, carrying no color, no preformatted strings, no
ordering guarantee — and `internal/report` is untouched. Reversing this decision
means deleting a directory and one call site, not unpicking a rewrite.

**`internal/report/table.go` is not ported.** It keeps its `text/tabwriter` and
its raw ANSI constants. Two styling systems in one binary is fine precisely
because they never render the same thing, and rewriting the table would change
output that CI greps and the README shows.

**Pindrop now scans its own dependencies.** Whatever these 30 modules carry, the
product reports on it.

Four properties of the implementation are load-bearing:

**Everything renders to stderr.** stdout carries the report and must stay safe to
pipe into `jq`. This is the same rule that already puts slog on stderr. The
display is stopped, and the cursor restored, before a single byte of the report
is written, so a frame can never interleave with the table.

**It degrades rather than misbehaves.** `ResolveMode` is a pure function: a
non-terminal stderr, `TERM=dumb` or unset, or `--log-level debug` all fall back
to plain lines. The debug rule is not defensive coding — slog writes to stderr,
and any concurrent writer shreds a bubbletea frame. That the animation works at
all depends on every adapter buffering its child's output, which is now an
invariant a future adapter can break.

**`--no-color` does not disable the animation.** It disables color. Someone who
wants no motion has `--progress plain`.

**Ctrl-C ownership does not move.** `tea.WithoutSignalHandler()` and
`tea.WithInput(nil)`: `cmd/pindrop` already owns SIGINT via
`signal.NotifyContext` and already treats `context.Canceled` as success, and the
display never reads stdin — reading it would steal keystrokes and break when
stdin is a pipe.

## Consequences

- A scan shows four rows updating live, with a running total. Skipped scanners
  appear as dimmed rows pointing at `pindrop setup` rather than as a block of
  text above the display.
- The footer says **raw findings**, deliberately: it sums what each scanner
  reported, before cross-tool dedup, so it is legitimately larger than the number
  the report shows. Calling it "findings" would make the table look lossy.
- Severity and status are always words, never color alone — the same rule the
  dashboard's badges follow, and what keeps plain mode readable.
- `go.sum` grew by 30 modules. Renovate/dependabot noise increases accordingly.
- New rule: **no package other than `internal/tui` may import bubbletea or
  lipgloss.** If a second one needs to, that is a signal to reconsider this ADR.

## Alternatives considered

**A hand-rolled ANSI spinner in `internal/report`.** Roughly 150 lines: a ticker,
cursor-up redraw of a fixed row count, a braille cycle. Zero new dependencies,
and honestly the cheaper option for exactly this feature. Rejected because the
next two things on the roadmap — Phase 1's new/resolved/regressed diff view and a
triage prompt — are interactive, and hand-rolling those means reimplementing a
render loop, input handling, and terminal restoration badly. The confinement to
`internal/tui` is what makes reversing this cheap if that reasoning turns out to
be wrong.

**No animation; print a line per scanner as it completes.** Cheapest of all.
Rejected because concurrency makes it useless: nothing prints until the first
tool finishes, and the slowest determines the wall clock. This is exactly what
plain mode does, and plain mode exists because in a log file it is the right
answer — but it is not the answer for a human waiting at a prompt.

**A channel of events instead of an `Observer` interface.** Rejected: it forces
`scan.Run` to own a lifecycle it does not have — who closes it, what happens when
nobody drains it, what cancellation means for a half-drained channel — and every
existing caller and test would need a drain goroutine. Its only advantage is
backpressure, which is precisely what we do not want: a slow renderer must never
slow a scan.

**`teatest` for testing the model.** Rejected as another dependency for something
already easy: the models are tested by folding messages through `Update` and
asserting on `View()`, with no terminal involved.

**Rendering to stdout.** Rejected outright. It would break
`pindrop scan . --format json | jq`, which is a supported and documented use.
