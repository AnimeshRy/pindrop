# 0005 — mise as an optional layer, not a build dependency

**Status:** Accepted
**Date:** 2026-08-03

## Context

Five tool versions are pinned in three or four different places:

| Tool | Declared in |
|---|---|
| Go 1.26.5 | `go.mod` toolchain directive, `ci.yml` `GO_VERSION` |
| Node 22.13 | `web/package.json` engines, `ci.yml` `NODE_VERSION` |
| pnpm 11.18.0 | `web/package.json` packageManager |
| Trivy 0.72.0 | `Makefile` `TRIVY_VERSION`, and a **hardcoded literal** in `ci.yml` |
| golangci-lint v2.12.2 | `Makefile`, `ci.yml` `GOLANGCI_LINT_VERSION` |

Trivy had already drifted into being a variable in one file and a literal in
another — the kind of divergence that ends with CI and a laptop scanning with
different scanner versions, which for a tool whose fingerprints are a data
contract is worse than it sounds.

[mise](https://mise.jdx.dev) can express all five in one file.

## Decision

Add `mise.toml`, and make it **optional**. The Makefile prefers a mise-managed
tool when one exists and installs a pinned copy into `./bin` otherwise. CI stays
on `actions/setup-go` and `actions/setup-node`.

### Why optional

**Contributors must not need mise to build.** A security scanner's first
impression is `git clone && make setup`. Requiring a version manager first is a
worse onboarding trade than a duplicated version string.

**CI caching is better with the setup-* actions.** `setup-go` caches the module
and build cache keyed on `go.sum`; `setup-node` caches the pnpm store keyed on
the lockfile. `jdx/mise-action` caches tool installs, which is the part that was
never the bottleneck here.

**Two install paths for Trivy is a feature, not a bug.** mise pulls Trivy from
its own registry; `make trivy` uses Trivy's `install.sh` at a pinned tag. Since
[ADR 0002](0002-trivy-subprocess.md) pins Trivy specifically because its release
channel was compromised twice in 2026, keeping the vendor path as the one CI and
`make setup` use — with mise's registry as a local convenience — is deliberate.

### The GOROOT trap

mise sets `GOROOT` by default (`go.set_goroot = true`). That is exactly the
failure this repo already carries a workaround for: with `GOROOT` exported, the
moment the go driver re-execs into a different toolchain it compiles against the
previous install's stdlib and fails with

```
compile: version "goX" does not match go tool version "goY"
```

Two mitigations, both kept:

1. `mise.toml` sets `go = "1.26.5"`, byte-identical to `go.mod`'s `toolchain`
   directive, so no re-exec ever happens. Loosening this to `"1.26"` or
   `"latest"` reintroduces the bug.
2. `[settings.go] set_goroot = false`, and the Makefile's
   `GO := env -u GOROOT go` stays as the seatbelt for shells that export it for
   unrelated reasons.

### golangci-lint

Under mise it comes from the `go:` backend, so it is **built with** Go 1.26.5.
That removes the "built with go1.25, cannot analyze a go1.26.5 module" refusal
at its root rather than by forcing `GOTOOLCHAIN` at install time.

The Makefile resolves it with `mise which`, not `command -v`, precisely so a
system-wide golangci-lint **v1** on `PATH` is never selected — it cannot parse
this repo's v2 config at all.

## Consequences

- One file to read for every pinned version; `mise.toml` is now the doc of
  record, and the Makefile/CI copies must be updated alongside it. Nothing
  enforces that yet.
- `make <target>` resolves tool paths at startup, so a fresh `mise install` is
  only picked up on the *next* invocation. `make mise` says so on completion.
- Developers with mise skip `corepack enable pnpm`; `make web-install` detects
  this and skips it rather than layering a second pnpm shim.
- CI behavior is unchanged, so this cannot break the pipeline.

## Alternatives considered

| Rejected | Why |
|---|---|
| mise required, incl. `jdx/mise-action` in CI | Loses `setup-go`/`setup-node` dependency caching, makes a version manager a prerequisite for a first build, and routes Trivy away from its vendor install path |
| `.tool-versions` (asdf format) | mise reads it, but it cannot express the `go:` backend tools or the `set_goroot` setting — the two things that carry the real value here |
| Do nothing | Workable, but Trivy's version had already drifted between `Makefile` and `ci.yml` |
| Devcontainer / Nix | Heavier than the problem. The pain was five version strings, not environment reproducibility |
