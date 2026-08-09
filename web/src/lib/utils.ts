import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/**
 * Merge Tailwind class names, letting later classes override earlier ones even
 * when they belong to the same utility group. This is the standard shadcn/ui
 * helper and is what component `className` props rely on.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}

/** Format a location as `path:line`, omitting the line when there isn't one. */
export function formatLocation(path: string, line?: number): string {
  return line && line > 0 ? `${path}:${line}` : path
}

const RELATIVE = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })

const RELATIVE_UNITS: ReadonlyArray<[Intl.RelativeTimeFormatUnit, number]> = [
  ['year', 365 * 24 * 60 * 60_000],
  ['month', 30 * 24 * 60 * 60_000],
  ['day', 24 * 60 * 60_000],
  ['hour', 60 * 60_000],
  ['minute', 60_000],
  ['second', 1000],
]

/**
 * Format a timestamp as "3 days ago".
 *
 * A repository list is scanned for staleness rather than read for dates, so the
 * relative form is what the eye actually needs. The absolute timestamp is still
 * exposed everywhere this is used, via `title`, because "which run was that"
 * needs the real thing.
 */
export function formatRelative(iso: string): string {
  const at = new Date(iso)
  if (Number.isNaN(at.getTime()) || at.getTime() === 0) {
    return 'never'
  }

  const deltaMs = at.getTime() - Date.now()
  for (const [unit, ms] of RELATIVE_UNITS) {
    if (Math.abs(deltaMs) >= ms) {
      return RELATIVE.format(Math.round(deltaMs / ms), unit)
    }
  }
  return 'just now'
}

/** Format a timestamp in full, for a `title` attribute or a detail line. */
export function formatAbsolute(iso: string): string {
  const at = new Date(iso)
  return Number.isNaN(at.getTime()) ? iso : at.toLocaleString()
}

/**
 * Shorten a commit hash to the conventional seven characters. Anything that is
 * not a hash — a tag, an empty string — is returned untouched.
 */
export function shortCommit(commit?: string): string {
  if (!commit) {
    return ''
  }
  return /^[0-9a-f]{7,}$/i.test(commit) ? commit.slice(0, 7) : commit
}
