# 0007 — Supabase Auth for cloud mode

**Status:** Accepted
**Date:** 2026-08-05

## Context

Pindrop ships as one embedded SPA inside a Go binary ([ADR 0003](0003-embedded-spa.md)).
Self-hosted users run `pindrop serve` on localhost with no accounts. The online
product needs Google and GitHub sign-in without forking the frontend or shipping
two binaries.

Phase 3 will add Postgres and org tenancy. Auth must not invent a user schema
that Phase 3 has to retrofit.

## Decision

- **Runtime mode switch.** `GET /api/v1/config` returns `self-hosted` or
  `cloud` plus Supabase URL and publishable key. One build artifact serves both
  deployments.
- **Supabase Auth in the browser** with PKCE (`@supabase/supabase-js`). OAuth
  providers: Google and GitHub. No GitHub `repo` scope at login — repository
  access belongs to the Phase 5 GitHub App.
- **Server-side verification** in `internal/auth`: ES256 only, JWKS from
  `<project>/auth/v1/.well-known/jwks.json`, cached keys with rate-limited
  refresh. Protected routes require `Authorization: Bearer <access_token>`.
- **No `profiles` table yet.** Display name comes from Supabase `user_metadata`
  and verified JWT claims until Phase 3 migrations define org-scoped identity.

Cloud mode is enabled with `PINDROP_MODE=cloud`, `PINDROP_SUPABASE_URL`, and
`PINDROP_SUPABASE_PUBLISHABLE_KEY` (or matching `pindrop serve` flags).

## Consequences

- Self-hosted behavior is unchanged when mode is unset or `self-hosted`.
- Cloud API returns 401 without a valid token; the UI redirects to `/login`.
- Changing JWT verification (algorithms, claim rules) is a security contract —
  treat it like a fingerprint change and document it.
- Operators must enable Google/GitHub providers and redirect URLs in the Supabase
  dashboard; the MCP server cannot configure Auth providers.

## Alternatives considered

| Rejected | Why |
|---|---|
| Two Vite builds (`VITE_PINDROP_MODE`) | Doubles release matrix; runtime config is enough while cloud and self-hosted share one UI |
| Separate cloud frontend | Violates embedded-SPA distribution story for the CLI binary |
| Frontend-only auth | Leaves scan JSON open to anyone who can reach the server in cloud deployments |
| HS256 with JWT secret on the server | Supabase projects on signing keys use ES256 JWKS; accepting HMAC would be an algorithm-agility footgun |
| `profiles` table now | Phase 3 requires `org_id` on every table from the first migration |
