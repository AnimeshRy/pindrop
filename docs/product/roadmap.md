# Roadmap

Each phase ships something usable on its own. The ordering is deliberate:
identity before persistence, persistence before multi-tenancy, and the noise
reduction that justifies the product only after there is a corpus to reduce.

## Phase 0 — Foundations ✅ done

The scaffold. One scanner, one binary, no server.

- `pindrop scan` runs Trivy as a subprocess and normalizes its output
- `scan.Finding` domain model with per-category fingerprinting
- `table`, `json`, and `sarif` renderers
- `pindrop serve` serving an embedded React dashboard from `go:embed`
- Lint, format, test, and CI

**Deliberately not done yet:** nothing is persisted. Fingerprints are computed
and displayed but not stored, so there is no cross-scan comparison. That is
Phase 1, and getting the identity function right now is what makes it cheap.

## Phase 1 — Local state and lifecycle

The first phase where the product does something a shell script cannot.

- Persist scans to `.pindrop/` (SQLite or JSON — SQLite once queries get real)
- Diff consecutive scans by fingerprint: **new**, **still open**, **resolved**,
  **regressed**
- `pindrop scan --diff` showing only what changed since last run
- Triage: `pindrop ignore <fingerprint> --reason "..."`, persisted and honored
  forever
- `pindrop status` summarizing open issues

**Success test:** mark a finding as a false positive, reformat the file it lives
in, rescan — it stays suppressed. If that fails, the fingerprint is wrong.

## Phase 2 — More scanners

Cross-tool dedup only becomes real once there is more than one tool.

- **Gitleaks** (MIT) — secrets, as a second opinion against Trivy's
- **Opengrep** — SAST. Preferred over Semgrep CE because of the rule-registry
  licensing change; see [scanners.md](../architecture/scanners.md)
- Merge findings that different tools report for the same problem, and use
  agreement as a confidence signal
- Parallel execution is already in place via `scan.Run`

## Phase 3 — Server and accounts

Where it becomes a product rather than a tool.

- Postgres, `sqlc` + `pgx/v5`, `goose` migrations, `river` for background jobs
- Organizations, users, API keys — **`org_id` on every table from the first
  migration**; retrofitting tenancy is miserable and a cross-tenant leak in a
  security product is fatal
- `pindrop login` / `pindrop push` sending local scan results to the server
- Gin enters here, for a real API surface; stdlib `net/http` was correct for
  Phase 0's static file server

## Phase 4 — The real dashboard

- Findings, filtering, triage from the browser
- Trend over time, per-repository views
- Replace `httpapi.FileSource` with a database-backed source; the interface
  already exists for exactly this swap

## Phase 5 — GitHub App

The moment it stops being something you remember to run.

- GitHub App (not OAuth PATs — installation tokens are scoped and expire hourly)
- Webhook on pull request → clone → scan → inline review comments
- Post only findings **new in this PR**, which Phase 1's diff already computes
- Envelope-encrypt any stored token via KMS; never log one

## Phase 6 — Prioritization

The phase that delivers the thesis.

- **EPSS** and **CISA KEV** enrichment (both free feeds)
- Direct vs transitive dependency depth
- Dev-only dependency detection — a huge share of CVEs never ship
- Reachability analysis: is the vulnerable function actually called?
- **VEX** output via `openvex/go-vex`
- Continuous SBOM re-evaluation: match stored SBOMs against new advisories
  daily, so new vulnerabilities surface without rescanning anything

## Later

- AWS and Kubernetes posture (Prowler, Kubescape)
- Rules tuned for AI-generated code patterns, including hallucinated packages
- Auto-fix pull requests
