import { SEVERITIES, type Severity, type Summary } from '@/lib/api'
import { cn } from '@/lib/utils'

const accent: Record<Severity, string> = {
  critical: 'text-red-600 dark:text-red-400',
  high: 'text-orange-600 dark:text-orange-400',
  medium: 'text-amber-600 dark:text-amber-400',
  low: 'text-yellow-600 dark:text-yellow-500',
  info: 'text-blue-600 dark:text-blue-400',
  unknown: 'text-zinc-500',
}

/**
 * Counts by severity.
 *
 * Severities with no findings are still rendered, greyed out. A zero that is
 * visibly zero is more reassuring than an absent tile, which reads as "did it
 * even check?".
 */
export function SummaryTiles({ summary }: { summary: Summary }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
      {SEVERITIES.map((severity) => {
        const count = summary.bySeverity[severity] ?? 0
        return (
          <div
            key={severity}
            className={cn(
              'rounded-lg border p-4 transition-opacity',
              count === 0 && 'opacity-50',
            )}
            style={{ borderColor: 'var(--border)', background: 'var(--card)' }}
          >
            <div
              className={cn('text-2xl font-semibold tabular-nums', accent[severity])}
            >
              {count}
            </div>
            <div
              className="mt-0.5 text-xs uppercase"
              style={{ color: 'var(--muted-foreground)' }}
            >
              {severity}
            </div>
          </div>
        )
      })}
    </div>
  )
}
