# vulnerable-app

A deliberately insecure fixture used to exercise `pindrop scan` end to end.

**This is not a real application.** Nothing here is deployed, imported, or
executed. It exists so that `make run-scan` produces real findings without
needing a live project to point at.

## What it triggers

Verified against Trivy v0.72.0:

| File | Category | Findings |
|------|----------|----------|
| `package-lock.json` | vulnerability | CVEs in pinned `cross-spawn@7.0.3` and `lodash@4.17.20` |
| `Dockerfile` | misconfiguration | `DS-0002` runs as root, `DS-0026` no healthcheck |

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
