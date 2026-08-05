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

### Two things must land before persistence, not after

Both change fingerprints. Doing them now costs nothing because nothing is stored;
doing them after Phase 1 is a data migration that orphans triage decisions.

- ✅ **Cross-tool identity and dedup** — done ahead of schedule, because it turned
  out the fingerprint alone did not merge Trivy and OSV-Scanner reports of one
  vulnerability. `scan.Dedup`, `canonical.go`, and
  [ADR 0006](../decisions/0006-canonical-identity-before-dedup.md).
- ⬜ **Resource identity for cloud and cluster findings** — a security group or an
  IRSA role has no file path, and keying on an ephemeral resource ID would report
  everything as fixed-and-reintroduced on the next node rotation. Needed before
  any of the EKS or AWS work below. Needs an ADR.

## Phase 2 — More scanners

Dedup landed in Phase 1, so each scanner below should now *reduce* the issue count
relative to the raw findings it adds. If one does not, it needs a filter before it
ships — see [scanners.md](../architecture/scanners.md).

Ordered cheapest-and-most-informative first:

- ✅ **OSV-Scanner** (Apache-2.0, Go) — second SCA opinion on a different advisory
  corpus, and the only free source of reachability (`--call-analysis`, opt-in
  because it compiles the target). Lets Phase 6's central premise be tested now
  rather than assumed. **Measured on the bundled fixture: 14 raw findings from two
  scanners merged to 8 — the same count Trivy alone produced, with four findings
  now corroborated by both tools.**
- ✅ **Opengrep** — SAST, and the host engine for the AI-code rules that are the
  real differentiator. Preferred over Semgrep CE because of the rule-registry
  licensing change. **Taken before TruffleHog**, out of the order below: it was
  listed later on the assumption that its rule strategy was the biggest lift, and
  that turned out to be a licensing decision rather than a body of work — no
  redistributable ruleset exists, so Pindrop ships ten of its own
  ([ADR 0007](../decisions/0007-first-party-opengrep-rules.md)). TruffleHog's
  blocker, an ADR for sending discovered secrets to third-party APIs, is still
  open, so nothing was skipped over.
  **Measured on the bundled fixture: 11 new findings, all of them net new —
  a SAST finding has no dependency finding to merge with. The number that matters
  for this scanner is precision instead: 0 findings against `internal/`, `cmd/`,
  and `web/src/`.**
- **Trivy `k8s`** — EKS posture as a new `Target` kind, no new adapter. Blocked on
  resource identity above.
- **TruffleHog** (AGPL, subprocess only) — secrets, verified-only. Replaces
  Gitleaks in the plan: Trivy already does regex secrets, so a second regex engine
  adds matches rather than information, whereas TruffleHog's verifiers prove a
  credential is live. Its outbound verification calls need an ADR first.
- **zizmor** (MIT) — GitHub Actions workflows. Small scope, near-zero noise, and
  agent-written CI gets template injection wrong routinely.

Cross-tool SAST dedup stays unsolved: two engines' rule IDs for "SQL injection"
share no namespace to canonicalize onto. Deliberate — see ADR 0006. The Opengrep
adapter therefore populates no `Aliases`, which is the one place that omission is
correct rather than a bug.

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

- **Kubescape** (CNCF Incubating) for Kubernetes posture, if Trivy's `k8s`
  coverage proves thin
- **Prowler** for AWS/Azure/GCP posture — 600 checks across 44 compliance
  frameworks, so a curated check subset has to be decided *before* the adapter is
  written. Largest noise risk in the inventory.
- Rules tuned for AI-generated code patterns
- **Hallucinated-package detection.** Detection is entirely commercial today
  (Socket, Snyk, Aikido), so this is our code rather than an adapter — which is
  what makes it a moat. ~19.7% of packages recommended across 576k LLM-generated
  samples were hallucinations, and 2026 has live incidents propagated by agents
  executing their own output. A useful v1 needs no ML: does the package resolve,
  how old is the registry entry, how many downloads, and how close is the name to
  a high-download package.
- Auto-fix pull requests
