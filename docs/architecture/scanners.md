# Scanners

## The contract

```go
type Scanner interface {
    Name() string
    Preflight(ctx context.Context) error
    Scan(ctx context.Context, target Target) (Result, error)
}
```

Rules every adapter must honor:

1. **`Name()` is persisted.** Lowercase, constant across versions.
2. **`Preflight` wraps `scan.ErrUnavailable`** and its message is shown directly
   to the user, so it must say how to fix the problem. Use
   `scan.UnavailableError` with a `Hint`.
3. **Every returned finding has `Scanner` and `Fingerprint` set.**
4. **No findings is not an error.** Return an empty slice and a nil error; a
   non-nil error means the tool itself failed.
5. **Safe for concurrent use** — `scan.Run` fans scanners out in parallel.
6. **Respect `ctx`.** Use `exec.CommandContext` so cancellation kills the child
   process rather than leaking it.

## Subprocess, not library

Adapters shell out. For Trivy specifically this is a researched decision with a
decisive argument — Trivy downloads its vulnerability database at runtime no
matter how you invoke it, so embedding buys no self-contained binary while
costing a ~500-module dependency graph. See
[ADR 0002](../decisions/0002-trivy-subprocess.md).

The general form of the argument holds for most scanners, and there is a hard
constraint for at least one: TruffleHog is AGPL-3.0, so importing it would
infect the whole codebase.

Practical rules for subprocess adapters:

- Pass the tool's "don't fail on findings" flag (`--exit-code 0` for Trivy) so a
  non-zero exit unambiguously means the tool broke.
- Hand-roll the result structs. Importing the tool's own types to save sixty
  lines drags in its entire dependency tree.
- Decode defensively — fields are usually `omitempty`, and top-level arrays are
  often absent rather than empty.
- Capture stderr separately and include a trimmed tail in error messages.

## Adding a scanner

1. Create `internal/scan/<tool>/`.
2. `<tool>.go` — the `Scanner` implementation, with functional options
   (`WithBinary`, `WithTimeout`, …). Follow `trivy/trivy.go`.
3. `report.go` — hand-written structs mirroring the tool's output. Capture real
   output; do not write them from documentation. (The Trivy adapter originally
   read an `AVDID` field that documentation mentioned and the tool does not
   actually emit.)
4. `convert.go` — map into `scan.Finding`, including severity vocabulary.
5. `testdata/report.json` — a **captured** golden report, so tests run without
   the tool installed. Note in the file which parts are captured and which, if
   any, are derived.
6. Register it in the slice in `internal/cli/scan.go`. That is the only place
   outside the new package that changes.

## Tool inventory and licensing

Licensing constrains what we can do, and getting it wrong is expensive.

| Tool | License | Language | Status | Notes |
|---|---|---|---|---|
| **Trivy** | Apache-2.0 | Go | **In use** | Subprocess. SCA, IaC, secrets, licenses in one invocation |
| **Gitleaks** | MIT | Go | Phase 2 | Secrets. Safe to embed if ever useful |
| **Opengrep** | LGPL | OCaml | Phase 2 | SAST. Preferred over Semgrep CE — see below |
| **Grype / Syft** | Apache-2.0 | Go | Maybe | Second SCA opinion; Syft for SBOM |
| **KICS** | Apache-2.0 | Go | Maybe | IaC, if Trivy's misconfig coverage proves thin |
| **Kubescape** | Apache-2.0 | Go | Later | Kubernetes posture |
| **Prowler** | Apache-2.0 | Python | Later | AWS posture |
| **TruffleHog** | **AGPL-3.0** | Go | Careful | **Subprocess only — never import** |
| **Checkov** | Apache-2.0 | Python | Skipped | Trivy covers IaC and stays in-process-free |

### Two specific traps

**TruffleHog is AGPL-3.0.** Running it as a separate process is fine — separate
processes are not derivative works. Importing it as a Go library would place the
entire Pindrop codebase under AGPL, which is incompatible with the commercial
plan. This must never happen by accident.

**Semgrep's rule registry is not open source.** Semgrep CE itself is LGPL, but
the registry rules moved to a restrictive license that prohibits building
competing products. That is exactly what we are doing. Use **Opengrep** (the
2025 fork) or curate our own rules; do not ship Semgrep's registry.

**Trivy's release channel was compromised twice in 2026** (a malicious `v0.69.4`
and a compromised `trivy-action`). Pin by version and verify checksums in any
install path we control. CI pins `v0.72.0` explicitly.

## Filtering is part of the adapter's job

An adapter that faithfully forwards everything its tool reports is not finished.
Trivy's license scanner classifies **every** license it identifies, so enabling
it naively produced 24 MIT/Apache/BSD/ISC entries against 8 real problems when
scanning Pindrop itself — a 4x noise multiplier from one sub-scanner.

`actionableLicense` in `trivy/convert.go` keeps only `forbidden`, `restricted`,
and `reciprocal` — the copyleft categories that can actually oblige a commercial
product to do something. `notice`, `permissive`, `unencumbered`, and `unknown`
are dropped. A user who wants the full inventory wants an SBOM, which is a
different feature.

**Apply the same test to every new adapter:** after wiring it up, scan a
healthy repository. If the count jumps by more than a handful, the adapter is
forwarding noise and needs a filter before it ships.

## Severity mapping

Each tool has its own vocabulary; adapters normalize. Trivy's mapping lives in
`trivy/convert.go`:

| Tool value | `scan.Severity` |
|---|---|
| `CRITICAL` | `critical` |
| `HIGH` | `high` |
| `MEDIUM` | `medium` |
| `LOW` | `low` |
| `INFO` | `info` |
| anything else | `unknown` |

Unrecognized values map to `unknown` rather than being guessed at. A wrong
severity is worse than an absent one, because it distorts ranking.
