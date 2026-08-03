import type { Severity } from '@/lib/api'
import { cn } from '@/lib/utils'

/**
 * Severity styling. Colors carry meaning here, so each badge also states its
 * severity in text — color alone would fail for colorblind users and in
 * grayscale printouts.
 */
const styles: Record<Severity, string> = {
  critical: 'bg-red-600/15 text-red-700 dark:text-red-400 ring-red-600/30',
  high: 'bg-orange-600/15 text-orange-700 dark:text-orange-400 ring-orange-600/30',
  medium: 'bg-amber-500/15 text-amber-700 dark:text-amber-400 ring-amber-500/30',
  low: 'bg-yellow-500/15 text-yellow-700 dark:text-yellow-400 ring-yellow-500/30',
  info: 'bg-blue-500/15 text-blue-700 dark:text-blue-400 ring-blue-500/30',
  unknown: 'bg-zinc-500/15 text-zinc-600 dark:text-zinc-400 ring-zinc-500/30',
}

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity
  className?: string
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium uppercase ring-1 ring-inset',
        styles[severity] ?? styles.unknown,
        className,
      )}
    >
      {severity}
    </span>
  )
}
