import { normalizeSeverity, type Severity } from '@/lib/api'
import { cn } from '@/lib/utils'

/**
 * Severity styling. Color carries meaning here, so the badge also spells out
 * the severity in text — color alone would fail for colorblind users and in
 * grayscale printouts.
 */
const styles: Record<Severity, string> = {
  critical: 'bg-red-600/15 text-red-700 ring-red-600/30 dark:text-red-400',
  high: 'bg-orange-600/15 text-orange-700 ring-orange-600/30 dark:text-orange-400',
  medium: 'bg-amber-500/15 text-amber-700 ring-amber-500/30 dark:text-amber-400',
  low: 'bg-yellow-500/15 text-yellow-700 ring-yellow-500/30 dark:text-yellow-500',
  info: 'bg-blue-500/15 text-blue-700 ring-blue-500/30 dark:text-blue-400',
  unknown: 'bg-zinc-500/15 text-zinc-600 ring-zinc-500/30 dark:text-zinc-400',
}

export function SeverityBadge({
  severity,
  className,
}: {
  severity?: string
  className?: string
}) {
  const normalized = normalizeSeverity(severity)
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium uppercase ring-1 ring-inset',
        styles[normalized],
        className,
      )}
    >
      {normalized}
    </span>
  )
}
