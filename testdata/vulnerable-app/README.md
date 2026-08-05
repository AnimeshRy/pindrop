# vulnerable-app

A deliberately insecure fixture used to exercise `pindrop scan` end to end.

**This is not a real application.** Nothing here is deployed, imported, or
executed. It exists so that `make run-scan` produces real findings without
needing a live project to point at.

## What it triggers

Verified against Trivy v0.72.0, OSV-Scanner v2.4.0, and Opengrep v1.26.0:

| File | Category | Findings |
|------|----------|----------|
| `package-lock.json` | vulnerability | CVEs in pinned `cross-spawn@7.0.3` and `lodash@4.17.20` |
| `Dockerfile` | misconfiguration | `DS-0002` runs as root, `DS-0026` no healthcheck |
| `src/routes.js` | code | 5 — `js-eval-user-input` ×2, `js-child-process-command-injection`, `js-sql-query-from-user-input`, `js-jwt-verify-algorithm-none` |
| `src/report.py` | code | 4 — `py-sql-string-formatting`, `py-subprocess-shell-true`, `py-yaml-unsafe-load`, `py-flask-debug-enabled` |
| `src/admin.go` | code | 2 — `go-sql-query-from-sprintf`, `go-exec-command-from-request` |

## About `src/`

These files exist because a SAST engine had nothing to read: before Opengrep was
wired up this fixture held only a lockfile, a Dockerfile, and `.env.example`.

Three properties are deliberate and easy to break:

- **Each vulnerable function has a safe counterpart** — `findUserSafely`,
  `orders_for_safely`, `rotate_logs`, `load_config_safely`,
  `lookupHandlerSafely`. These must **not** be reported. They are how the rules'
  `focus-metavariable` sinks and `pattern-not` clauses stay honest; a rule that
  flags the parameterized form of a query is worse than no rule.
- **`js-eval-user-input` fires twice in one file, on purpose.** Identity for a
  code finding is rule ID + path + normalized snippet, so two hits of one rule in
  one file are the case that catches an adapter which drops `extra.lines` — they
  would silently merge into one.
- **There is no `go.mod` and no `requirements.txt`.** Adding either would give
  Trivy and OSV-Scanner a new dependency source and change their finding counts,
  which `docs/architecture/scanners.md` records and re-measures. The
  `src/` directory is also invisible to the Go toolchain because it sits under
  `testdata/`, so `admin.go` is never compiled or vetted.

Do not reformat these files as part of an unrelated change. Reindenting them is a
manual test — the code findings' fingerprints must not move — and doing it
silently removes the signal.

## Why there is no secret here

Secret scanning is deliberately **not** exercised by this fixture, and
`.env.example` is not expected to produce a finding — the AWS key in it is the
canonical value from AWS's own documentation, which scanners allowlist.

Committing a realistic-looking credential to make the secret scanner fire would
mean every future scan of the Pindrop repository reports a critical secret in
its own test data. That is a bad trade for one integration assertion.

Secret conversion is covered instead by the golden report at
`internal/scan/trivy/testdata/report.json`, which contains a real (redacted)
`github-pat` detection captured from Trivy.

## Expect the CVE list to drift

Vulnerability findings depend on the advisory database, so the exact set changes
over time as new CVEs are published against these pinned versions. That is
expected and is why no test asserts on them. Tests that need a fixed set use the
golden report.
