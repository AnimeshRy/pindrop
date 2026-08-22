import type { DeltaCounts } from '@/lib/api'
import { cn } from '@/lib/utils'

/**
 * What a run changed, as a compact row of counts.
 * Wording uses "no longer detected" rather than "fixed" on purpose.
 */
export function DeltaBadges({
  delta,
  className,
}: {
  delta: DeltaCounts
  className?: string
}) {
  const parts: Array<{ key: string; text: string; tone: string }> = []

  if (delta.new > 0) {
    parts.push({
      key: 'new',
      text: `+${delta.new} new`,
      tone: 'text-red-700 dark:text-red-400',
    })
  }
  if (delta.regressed > 0) {
    parts.push({
      key: 'regressed',
      text: `↺ ${delta.regressed} returned`,
      tone: 'text-purple-700 dark:text-purple-400',
    })
  }
  if (delta.fixed > 0) {
    parts.push({
      key: 'fixed',
      text: `− ${delta.fixed} no longer detected`,
      tone: 'text-emerald-700 dark:text-emerald-400',
    })
  }

  if (parts.length === 0) {
    return (
      <span
        className={cn('text-xs', className)}
        style={{ color: 'var(--muted-foreground)' }}
      >
        no change
      </span>
    )
  }

  return (
    <span
      className={cn('flex flex-wrap items-center gap-x-2 gap-y-1 text-xs', className)}
    >
      {parts.map((part, index) => (
        <span key={part.key} className="flex items-center gap-2">
          {index > 0 && (
            <span aria-hidden style={{ color: 'var(--muted-foreground)' }}>
              ·
            </span>
          )}
          <span className={cn('font-medium whitespace-nowrap tabular-nums', part.tone)}>
            {part.text}
          </span>
        </span>
      ))}
    </span>
  )
}
