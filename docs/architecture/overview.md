# Architecture overview

## Phase 0 as built

```
┌──────────────────────────────────────────────────────────────┐
│  pindrop (single binary, 7.4 MB, dashboard embedded)         │
│                                                              │
│  scan ──► Preflight ──► Run (parallel) ──► normalize ──►     │
│                             │                 │              │
│                             ▼                 ▼              │
│                        trivy adapter     Fingerprint         │
│                        (subprocess)           │              │
│                                               ▼              │
│                                    table │ json │ sarif      │
│                                               │              │
│  serve ──► net/http ──► /api/v1/* ◄───────────┘              │
│                     └─► embedded React SPA                   │
└──────────────────────────────────────────────────────────────┘
              │                              │
              ▼                              ▼
        trivy binary                  .pindrop/report.json
        (+ remote vuln DB)
```

No database, no network service, no accounts. A user runs `pindrop scan .`,
gets a ranked table, and optionally runs `pindrop serve` to browse the same
results in a browser.

## Data flow

1. **`cli.runScan`** parses flags, resolves the target to an absolute path, and
   constructs the scanner set. This is the composition root — the only place
   that knows Trivy exists.
2. **`scan.Preflight`** checks every scanner concurrently. A missing tool is
   reported here as setup guidance, before any work starts.
3. **`scan.Run`** executes scanners concurrently via `sync.WaitGroup.Go`. A
   scanner that fails does not discard the others' results; `Run` returns
   partial results alongside a joined error.
4. **The adapter** shells out, parses the tool's JSON into hand-written structs,
   and maps each entry to a `scan.Finding`, computing its fingerprint.
5. **`scan.Findings`** flattens and sorts: severity descending, then path, line,
   rule. Total and deterministic, so identical scans render identically.
6. **`report.Write`** dispatches to the requested renderer.

## Concurrency

Two Go traps this domain invites, and how they are handled:

- **Goroutine leaks.** `scan.Run` uses `sync.WaitGroup.Go` (Go 1.25) and always
  waits. Results are written to pre-sized slots indexed by position, so there is
  no shared mutable state and no mutex.
- **Hung subprocesses.** Every adapter uses `exec.CommandContext` with a
  timeout, so cancellation reaches the child. `main` installs
  `signal.NotifyContext`, so Ctrl-C propagates all the way down to Trivy.

`serve` shuts down with `context.WithoutCancel`, so the same Ctrl-C that
triggers shutdown does not immediately cancel it.

## The HTTP layer

Routes use Go 1.22 method-qualified `ServeMux` patterns, so no third-party
router is needed. `ServeMux` resolves by pattern specificity rather than
registration order, so `/api/v1/...` wins over the `/` catch-all — there is a
test asserting exactly that, because getting it wrong would silently serve HTML
where JSON belongs.

The SPA handler falls back to `index.html` for any unmatched path. Without that,
a browser loading `/findings` directly gets a 404 instead of the app shell and
client-side routing appears broken. `index.html` is always served `no-cache`
while hashed bundles under `/assets/` are cached immutably — a cached shell
would point at bundles a later build deleted.

`httpapi.FindingSource` is an interface with one file-backed implementation. It
re-reads on every request, so a scan in one terminal shows up on the next
refresh in another. Phase 3 swaps in a database implementation without touching
the handlers.

## Deliberate omissions

Worth recording so nobody thinks they were oversights:

- **No database.** Phase 0 stores nothing. Fingerprints are computed and shown
  but not compared across runs. Getting identity right first is what makes
  Phase 1 cheap.
- **No Gin.** A framework for one static-file route and three handlers is
  premature. Gin arrives in Phase 3 with a real API.
- **Auth in cloud mode only.** Self-hosted `serve` binds to `127.0.0.1` and
  keeps the API open. Cloud mode verifies Supabase ES256 access tokens on
  `/api/v1/findings`, `/api/v1/summary`, and `/api/v1/me`. See
  [ADR 0007](../decisions/0007-supabase-auth-cloud-mode.md).
- **No `encoding/json/v2`.** Still experimental behind `GOEXPERIMENT=jsonv2` in
  Go 1.26; slated to become the default in 1.27. Revisit then.

## Planned shape

```
CLI ──┐
      ├──► Connect API ──► Postgres (sqlc + goose)
Agent ┘         │              ▲
                └──► River ────┘   background jobs
GitHub App ─────┘
```

Connect-RPC rather than raw gRPC, so one protobuf schema serves browser clients,
the CLI, and remote scanning agents without an Envoy proxy in between. See
[ADR 0001](../decisions/0001-core-stack.md).
