# Repository layout

```
pindrop/
├── cmd/pindrop/          main; run() pattern, single os.Exit
├── internal/
│   ├── cli/              cobra commands — the composition root
│   ├── scan/             DOMAIN CORE: Finding, Scanner, Fingerprint
│   │   ├── trivy/        Trivy adapter (subprocess)
│   │   ├── osv/          OSV-Scanner adapter (subprocess)
│   │   ├── opengrep/     Opengrep adapter (subprocess) + rules/, go:embed'd
│   │   └── trufflehog/   TruffleHog adapter (subprocess; AGPL, never import)
│   ├── report/           renderers: table, json, sarif
│   ├── httpapi/          serve: SPA + read-only JSON API
│   └── buildinfo/        version identity
├── web/                  Vite + React SPA, and the go:embed declaration
├── docs/                 you are here
└── testdata/             fixtures for end-to-end runs
```

## Dependency direction

```
cmd/pindrop
    └── internal/cli ──────────┬── internal/scan ◄── internal/scan/{trivy,osv,opengrep,trufflehog}
                               ├── internal/report ──┘
                               ├── internal/httpapi
                               └── web (embed)
```

The arrows all point inward at `internal/scan`. That package imports nothing of
ours except the standard library.

## Why each boundary exists

### `internal/` everywhere, no `pkg/`

This is a product, not a library. There is no external consumer, so there is no
public API to keep stable. `internal/` makes that a compiler-enforced fact
rather than a convention. Promote something to `pkg/` on the day something
outside this module needs to import it, and not before.

### `internal/scan` holds Finding, Scanner, and Fingerprint together

The obvious-looking alternative — separate `finding` and `scanner` packages — is
worse for two reasons. Callers need the types to interact, so you would import
both packages to do anything useful. And `finding.Finding` stutters, which the
Go naming conventions specifically warn against.

The package is named for what it is about, not for what it contains.

### The scanner registry lives in `internal/cli`, not `internal/scan`

`internal/scan` defines the `Scanner` interface. `internal/scan/trivy`
implements it, so trivy imports scan. If scan also held a registry that
referenced trivy, that would be an import cycle.

Instead the CLI — the composition root — is the only place that knows which
concrete scanners exist and wires them together. This is "accept interfaces,
return structs" applied at the program level, and it means adding a scanner
touches exactly two places: the new subpackage, and the slice in `scan.go`.

### `web/embed.go` lives in `web/`, not `internal/`

Not a style choice. `//go:embed` patterns cannot reference paths outside their
own package directory, so the declaration has to sit beside the built assets.
`web/` is therefore the one directory holding both Go and TypeScript.

`web/dist/.gitkeep` is committed because the embed directive fails to compile
when the directory is missing, and a fresh clone has not run `pnpm build` yet.

### `internal/report` is separate from `internal/scan`

Rendering is not domain logic. Keeping SARIF's vocabulary — levels, rules,
partial fingerprints — out of the domain model means the domain does not
acquire fields that exist only to satisfy an output format.

## Where to add things

| Adding… | Goes in | Also touch |
|---|---|---|
| A scanner | `internal/scan/<tool>/` | the slice in `internal/cli/scan.go` |
| An output format | `internal/report/` | `Format` consts and `Write` |
| A CLI command | `internal/cli/` | `root.go` `AddCommand` |
| An API route | `internal/httpapi/server.go` | `routes()` |
| A finding field | `internal/scan/finding.go` | consider the fingerprint impact |
| A dashboard page | `web/src/routes/` | routes are file-based |

## Things that would be wrong here

- A `util`, `common`, or `helpers` package. Name packages for what they provide.
- `internal/scan` importing any adapter subpackage. That is the cycle the
  registry placement avoids.
- Business logic in `cmd/`. `main.go` should stay under 40 lines.
- `os.Exit` or `log.Fatal` outside `main()`. Return errors; skipped `defer`s in
  a subprocess-spawning program mean leaked processes.
