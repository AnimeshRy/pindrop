# 0003 — Embed the dashboard into the binary

**Status:** Accepted
**Date:** 2026-08-02

## Context

The dashboard needs rich interactivity: filterable tables that stay usable at
tens of thousands of rows, multi-select bulk triage, charts. It also needs to
ship as painlessly as possible to users who are not operators.

## Decision

Build a React SPA with Vite and embed the output into the Go binary via
`go:embed`. One artifact, one process, no separate frontend deployment.

**Stack:** Vite 8, React 19, TypeScript 6, Tailwind 4, TanStack Router / Query /
Table, shadcn/ui conventions, pnpm.

### Why a React SPA

A security dashboard is largely one enormous filterable table. TanStack Table is
the only library that handles that well at scale, and its ecosystem assumes
React. shadcn/ui gives dashboard-grade components under MIT with the source
vendored into the repo, so there is no component-library lock-in.

### Why embedded rather than separately deployed

Two deploy artifacts is a real adoption tax for a self-hostable tool. `docker
run pindrop` or `./pindrop serve` producing a working dashboard is how Grafana,
Gitea, and Coder got adopted. The binary is 7.4 MB with the UI included.

### Why not Next.js

No SSR requirement, and it would force a Node runtime alongside the Go binary —
exactly the second artifact this decision exists to avoid.

### Why not templ + HTMX

Genuinely tempting: pure Go, no JS build, faster to start. Rejected because the
interaction requirements — virtualized tables, multi-select triage, charts —
are where hypermedia approaches get painful, and those are the core of the
product rather than incidental polish.

## Consequences

Three settings are load-bearing and easy to break:

- **`base: './'` in `vite.config.ts`.** Assets must resolve regardless of the
  path the app is mounted at.
- **`tanstackRouter()` before `react()`** in the plugin array. The router plugin
  generates route modules that the React plugin then transforms.
- **SPA fallback in the Go handler.** Any unmatched non-API path must return
  `index.html`, or deep links 404 and client-side routing appears broken.

Cache headers matter: `index.html` is always `no-cache`, hashed bundles under
`/assets/` are immutable. A cached shell pointing at deleted bundles is a
white-screen outage. There is a test asserting the root path gets `no-cache` —
it caught a real bug where `/` bypassed that path.

`web/embed.go` must live in `web/` because embed patterns cannot traverse `..`.
`web/dist/.gitkeep` is committed so `go build` works on a fresh clone before
anyone runs `pnpm build`; `web.FS()` returns `ErrNotBuilt` in that state and
`serve` degrades to API-only with a page explaining how to build the UI.

## Alternatives considered

| Rejected | Why |
|---|---|
| Next.js | SSR unneeded; forces a Node runtime beside the Go binary |
| templ + HTMX | Loses on virtualized tables, bulk selection, and charts |
| Separate frontend deployment | Two artifacts; significant adoption friction |
| Vue / Svelte | Smaller table-component ecosystem; TanStack Table is React-first |
