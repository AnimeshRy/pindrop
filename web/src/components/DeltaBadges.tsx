import type { DeltaCounts } from '@/lib/api'
import { cn } from '@/lib/utils'

/**
 * What a run changed, as a compact row of counts.
 *
 * Only non-zero counts are shown, so a run that changed nothing says so in one
 * phrase instead of four zeroes. Each count carries a sign or glyph as well as
 * a colour — the same reason SeverityBadge does.
 *
 * The resolved count reads "no longer detected", never "fixed". A scanner
 * ceasing to report a finding is weaker evidence than a fix: the rule may have
 * changed, the file may have moved, or that scanner may not have run. Claiming
 * a fix we cannot prove is how a security tool loses a user's trust.
 *
 * The four numbers need not add up to a run's total, and that is not a bug: a
 * finding nobody could observe this run is counted in none of them.
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
    <span className={cn('flex flex-wrap items-center gap-x-2 gap-y-1 text-xs', className)}>
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
