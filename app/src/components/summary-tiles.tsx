import { SEVERITIES, type Counts, type Severity } from '@/lib/api'
import { cn } from '@/lib/utils'

const accent: Record<Severity, string> = {
  critical: 'text-red-600 dark:text-red-400',
  high: 'text-orange-600 dark:text-orange-400',
  medium: 'text-amber-600 dark:text-amber-400',
  low: 'text-yellow-600 dark:text-yellow-500',
  info: 'text-blue-600 dark:text-blue-400',
  unknown: 'text-zinc-500',
}

/** Severity count tiles for one run. Zero counts stay visible so gaps read as checked, not missing. */
export function SummaryTiles({ counts }: { counts: Counts }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
      {SEVERITIES.map((severity) => {
        const count = counts.bySeverity?.[severity] ?? 0
        return (
          <div
            key={severity}
            className={cn(
              'rounded-lg border p-4 transition-opacity',
              count === 0 && 'opacity-50',
            )}
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
          >
            <div className={cn('text-2xl font-semibold tabular-nums', accent[severity])}>
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
