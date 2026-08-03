# 0004 — Pin TypeScript to 6.x

**Status:** Accepted, expected to be temporary
**Date:** 2026-08-02

## Context

The project brief asked for the latest version of everything. `npm install
typescript` currently installs **7.0.2** — the Go-native compiler port.

It does not work with our linting stack.

## Decision

Pin `typescript: ~6.0.3`. Revisit when TypeScript 7.1 ships.

### Why

**`typescript-eslint@8.65.0` declares a peer range of `typescript >=4.8.4
<6.1.0` and cannot run on TS 7 at all.** The cause is upstream: TypeScript 7.0
ships no stable programmatic API — a new one is targeted for 7.1. The
TypeScript team's own guidance is that API consumers use the
`@typescript/typescript6` compatibility package in the meantime.

Losing type-aware linting on a security product's dashboard is a worse trade
than running a compiler one major behind.

**TS 7 also removed `baseUrl`** (deprecated in 6.0, a hard error in 7.0).
shadcn/ui's Vite installation docs still instruct you to add `"baseUrl": "."`,
so following them verbatim under TS 7 fails. Our `tsconfig.json` omits it and
relies on `paths` resolving relative to the config file, which works in both.

**Vite's own template agrees.** `create-vite`'s `template-react-ts` on `main`
pins `"typescript": "~6.0.2"` and has moved its lint script to `oxlint` rather
than ship ESLint against TS 7.

## Consequences

- Type-aware ESLint keeps working.
- We are one major behind on the compiler, and forgo the Go port's build-speed
  improvements. At this codebase size that is not measurable.
- `tsconfig.json` is already written to be TS 7-compatible — no `baseUrl`, no
  removed options — so the upgrade should be a version bump.

Other TS 6 defaults worth knowing, since they differ from older projects:
`strict: true`, `module: esnext`, `target: es2025`, and **`types: []`** — there
is no automatic `@types` discovery, so ambient packages must be listed
explicitly (we list `vite/client` and `node`).

## Revisit when

TypeScript 7.1 ships with a stable programmatic API **and** `typescript-eslint`
widens its peer range. Check
[typescript-eslint#12518](https://github.com/typescript-eslint/typescript-eslint/issues/12518).

## Alternatives considered

| Rejected | Why |
|---|---|
| TS 7 + drop ESLint | Loses type-aware linting on a security product |
| TS 7 + oxlint | Viable, and what create-vite now defaults to, but no `eslint-plugin-react-hooks` equivalent — and hook bugs are cheap to prevent, expensive to debug |
| TS 7 + Biome | Fast and credible, but no React Compiler hook rules and no `prettier-plugin-tailwindcss` class-sorting parity |
