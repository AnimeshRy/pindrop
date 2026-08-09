# Conventions

Enforced by `golangci-lint` where possible. The rest is convention with a
reason attached.

## Go

### Program structure

- **`os.Exit` and `log.Fatal` only in `main()`.** Everything else returns
  errors. This program spawns subprocesses; a skipped `defer` leaks them.
- **The `run()` pattern.** `main` is a single call plus one exit point.
- **`cmd/pindrop/main.go` stays under 40 lines.** Logic belongs in `internal/`.
- **No `init()`.** Initialize explicitly.
- **No mutable package-level state.** `buildinfo.version` is the sole exception,
  because link-time injection has no alternative — and it falls back to
  `debug.ReadBuildInfo()` so it is unset in normal builds.

### Packages

- Name for what the package provides. **No `util`, `common`, or `helpers`.**
- `internal/` for everything. Promote to `pkg/` only when an external consumer
  appears.
- Imports in two groups — stdlib, then everything else, with
  `github.com/AnimeshRy/pindrop` local-prefixed last. `goimports` handles it.

### Errors

- Wrap with `%w` and put it at the end: `fmt.Errorf("reading config: %w", err)`.
- Lowercase, no trailing punctuation.
- Sentinels (`scan.ErrUnavailable`) when callers need `errors.Is`; custom types
  (`scan.UnavailableError`) when they need structured detail.
- **Handle once** — log or return, never both.
- **User-facing errors must be actionable.** `"trivy not found in PATH"` plus an
  install URL, never `exec: "trivy": executable file not found`. This is a
  product requirement, not a style preference: our users are not security
  engineers.

### Style

- `gofumpt` plus `goimports`. Soft 99-column limit.
- Early returns; keep the happy path unindented.
- Doc comments on every exported symbol, starting with its name. Every package
  has a package comment.
- Comments explain **why**, not what. If a comment restates the code, delete it.
- Prefer stdlib. Every dependency in a security tool is supply-chain surface.
  The one deliberate exception is bubbletea/lipgloss, and it comes with a rule:
  **a third-party UI dependency is imported from exactly one package.** See
  [ADR 0011](../decisions/0011-bubbletea-for-progress.md).

### Concurrency

- `sync.WaitGroup.Go` (Go 1.25) over manual `Add`/`Done`.
- `ctx` is the first parameter, always propagated, never stored in a struct.
- Every subprocess uses `exec.CommandContext` so cancellation kills the child.
- Write to pre-sized slots indexed by position rather than sharing a slice
  behind a mutex.

### Tests

- Table-driven with subtests; `t.Parallel()` in both the parent and each subtest.
- Failure messages read `got = X, want Y`.
- **Golden fixtures must be captured from the real tool, not written from
  documentation.** The Trivy adapter read a nonexistent `AVDID` field for
  exactly this reason.
- Tests must pass with no external tools installed. Anything needing a real
  binary belongs in the CI integration job.
- Test behavior users depend on, not implementation. `fingerprint_test.go` is
  the model: it asserts the guarantees, not the hash algorithm.

## TypeScript

- ESLint 10 flat config, Prettier, no semicolons, single quotes, 88 columns.
- No `any`. Use `unknown` and narrow.
- `type` imports marked `import type` — `verbatimModuleSyntax` is on.
- No constructor parameter properties: `erasableSyntaxOnly` rejects them.
- Components in `src/components/`, routes in `src/routes/` (file-based).
- Wide content scrolls inside its own `overflow-x-auto` container. The page body
  must never scroll horizontally.
- Both color schemes are styled. Severity is never conveyed by color alone —
  every badge also states its severity in text.

## Documentation

- Update `docs/` in the same change that invalidates it.
- New non-obvious decision → new ADR. Reversing one → new ADR superseding the
  old, never an edit.
- Record what was **rejected and why**. That is the part that stops someone
  re-walking a dead end.

## Commits

Conventional Commits:

```
feat(scan): add gitleaks adapter
fix(httpapi): serve index.html with no-cache on the root path
docs(adr): record the trivy subprocess decision
```

Scopes match package names: `scan`, `trivy`, `report`, `httpapi`, `cli`, `web`,
`docs`, `ci`.

## Before pushing

```bash
make check     # lint + test, Go and frontend
```
