import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

import type { Repo } from '@/lib/api'

/** Merge Tailwind class names with later overrides winning. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}

/** Format a location as `path:line`, omitting the line when there isn't one. */
export function formatLocation(path?: string, line?: number): string | undefined {
  if (!path) {
    return undefined
  }
  return line && line > 0 ? `${path}:${line}` : path
}

/** Human-readable relative time for ISO timestamps. */
export function formatRelativeTime(iso: string): string {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) {
    return 'unknown'
  }
  const diffSec = Math.round((Date.now() - then) / 1000)
  if (diffSec < 60) {
    return 'just now'
  }
  const diffMin = Math.round(diffSec / 60)
  if (diffMin < 60) {
    return `${diffMin}m ago`
  }
  const diffHr = Math.round(diffMin / 60)
  if (diffHr < 48) {
    return `${diffHr}h ago`
  }
  const diffDay = Math.round(diffHr / 24)
  return `${diffDay}d ago`
}

/** Absolute timestamp for tooltips. */
export function formatAbsoluteTime(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) {
    return 'unknown'
  }
  return date.toLocaleString()
}

/** Short git commit hash for display. */
export function shortCommit(commit: string): string {
  return commit.length > 7 ? commit.slice(0, 7) : commit
}

/**
 * Primary location line for a repository in the UI.
 *
 * CLI sync records both the checkout path and the git `origin` remote.
 * Origin is stored for cross-machine dedup on the server; the listing should
 * show where the user actually synced from — not github.com for a local tree
 * that happens to have a GitHub remote configured.
 */
export function repoLocationLabel(repo: Repo): string {
  const cliPath = repo.links?.find((link) => link.source === 'cli')?.path
  if (cliPath) {
    return cliPath
  }
  if (repo.origin) {
    return repo.origin
  }
  return repo.links?.[0]?.path ?? 'No remote'
}

/** Git origin when it differs from the displayed checkout path. */
export function repoRemoteLabel(repo: Repo): string | undefined {
  const cliPath = repo.links?.find((link) => link.source === 'cli')?.path
  if (cliPath && repo.origin && repo.origin !== cliPath) {
    return repo.origin
  }
  return undefined
}
