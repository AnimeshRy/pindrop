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
