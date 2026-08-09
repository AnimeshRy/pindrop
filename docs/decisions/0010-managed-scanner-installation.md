# 0010 — Pindrop installs and verifies its own scanner binaries

**Status:** accepted
**Date:** 2026-08-07

## Context

Until now the only way to get the four scanners was `make setup`, which runs
Make rules that `curl | sh` two upstream install scripts, `go install`
OSV-Scanner, and download an Opengrep release asset chosen by a `case` over
`uname` output. That works for a contributor with a checkout. It is not a product:
a user who has a `pindrop` binary and nothing else has no Makefile, and the
adapters' binary resolution made this worse — they searched PATH and then the
directory holding the pindrop executable, so a `pindrop` in `/usr/local/bin` had
nowhere to put scanners it owned.

Two constraints shaped the answer.

Versions are a **parsing contract**, not a preference. Each adapter reads specific
fields out of specific report shapes, which is why the Makefile pins all four
rather than tracking latest, and why `docs/decisions/0002-trivy-subprocess.md`
records Trivy's release channel being compromised twice in 2026. Whatever
installs these tools has to pin them, and has to notice when what arrives is not
what was pinned.

TruffleHog is **AGPL-3.0**. The standing rule
(`docs/architecture/scanners.md`) is that it runs as a subprocess and never
enters the module graph — which is why the Makefile deliberately avoids
`go install` for it, unlike OSV-Scanner.

## Decision

`pindrop setup` downloads a pinned release of each scanner for the host platform,
verifies it against a **SHA-256 digest committed in `internal/toolinstall/manifest.json`
and embedded in the binary**, and installs it into `~/.pindrop/bin`.

Four decisions inside that:

**The managed directory is `~/.pindrop/bin`**, overridable with `PINDROP_HOME`.
XDG is not followed. A single fixed path can be printed literally in every error
message and prompt, and removed with one command a non-expert can be told to run;
`XDG_DATA_HOME` resolves differently per platform and per shell, which turns
"where did it put things" into a support question. `~/.cargo` and `~/.docker` set
the precedent. Note the collision of names is deliberate and harmless:
`~/.pindrop/` is the user's Pindrop home, while `<repo>/.pindrop/` holds that
repository's scan reports.

**Resolution gains a third location, searched last.** `internal/toolpath` now owns
the lookup that was copy-pasted into all four adapters (and had already drifted —
one used `filepath.Separator` where the others used `os.PathSeparator`). The order
is explicit `--<tool>-binary`, then PATH, then beside the pindrop binary, then the
managed directory. Managed comes last so a user's own Trivy on PATH keeps winning
and `./bin/pindrop` keeps finding `./bin/trivy`. The cost is that an *old* tool on
PATH still loses to Trivy's version floor instead of falling through to ours,
which is why `pindrop setup --check` reports the winning origin for each tool.

**Digests come from upstream's own checksum file where one exists**, and
generation aborts on a mismatch. Trivy, TruffleHog, and OSV-Scanner all publish
one. Opengrep publishes sigstore `.sig`/`.cert` files and no checksum list, so its
digest is computed from a download and is **trust-on-first-pin**; `make manifest`
prints the `cosign verify-blob` command to check it by hand.

**No `--skip-verify`, ever.** A security product that ships an escape hatch around
its own integrity check has not shipped an integrity check. Someone who needs an
unverified binary already has `--<tool>-binary /path`.

## Consequences

Be precise about what the manifest buys: **immutability, not provenance.** It makes
a release asset impossible to swap out *after* we pinned it — which is the actual
failure mode when a release is retagged or a channel is compromised. It cannot
detect a release that was already malicious when the digest was captured. Closing
that needs sigstore verification at install time, which is a deliberate follow-up.

- A first run downloads ~215 MB on macOS/arm64. The confirmation prompt states
  the size and the hosts before fetching anything, because "it downloaded 200 MB
  of third-party executables from somewhere" is not something a user should
  discover afterwards.
- A second run makes **zero network requests** and finishes in milliseconds,
  because `installed.json` records what was installed. That is the whole offline
  story, and it is why there is no `--offline` flag.
- Bumping a scanner version now means running `make manifest`. Forgetting fails a
  test in `internal/toolinstall` rather than a user's install.
- Scanner versions now live in both the Makefile and the manifest. That is one
  place too many; the test asserting they agree is what makes it survivable until
  the Makefile's copies are removed.
- A platform with no build for some tool (Windows, 32-bit, FreeBSD) still gets the
  others. This is the same principle as a missing scanner not failing a scan:
  reduced coverage beats no product.
- `setup --dir /usr/local/bin` will not overwrite a binary Pindrop did not
  install. Replacing a user's Homebrew Trivy requires `--force`.

## Alternatives considered

**Delegate to the host package manager.** Detect brew/apt and shell out. Rejected:
versions drift off the pins that make the report shapes parseable, coverage is
uneven across the four tools, and it needs sudo on Linux. It also gives up the
integrity check entirely, since we would no longer be the one fetching the file.

**`go install` for the Go-based tools.** Three of four are Go programs, and
OSV-Scanner was already installed this way. Rejected: it makes the version a
second source of truth outside the manifest, requires a Go toolchain on the user's
machine, and — the reason it matters here — normalizes a pattern that must never
be applied to TruffleHog.

**Verify against the upstream checksum file at install time.** Rejected as the
primary mechanism: it catches a corrupt download but not a compromised release,
because both come from the same channel. It is used at *generation* time instead,
where it is a genuine cross-check of two independently published values.

**Trust-on-first-use with no committed manifest.** Rejected. It would make the
retagged-release case undetectable, which is the one case the docs already record
happening.

**Cosign verification at install time.** The correct end state, and rejected only
for now: it would add a large dependency tree to a tool whose pitch includes
supply-chain surface, and Opengrep is the only tool where it would add signal the
committed digests do not already provide. Revisit with a new ADR.

**A URL template instead of literal per-platform URLs.** The four tools disagree on
every axis — `macOS-ARM64` vs `darwin_arm64` vs `osx_arm64` vs `manylinux_x86`,
`v`-prefixed tags against stripped versions, archive against bare binary. A
template encoding all of that is unreadable and its mistakes are invisible. A
literal URL is auditable in a diff, which is the property that matters for the
file guarding the supply chain. The generator owns the ugliness.

**Windows support in the first release.** Rejected: Opengrep publishes no
`windows/arm64` build at all, and shipping a `pindrop.exe` that cannot install its
own scanners is a support burden with no upside.
