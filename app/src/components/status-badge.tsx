import { normalizeStatus, STATUS_LABEL, type Status } from '@/lib/api'
import { cn } from '@/lib/utils'

/**
 * Lifecycle styling. Each badge carries a glyph as well as a color, and
 * spells the status out in words — color alone would fail for colorblind
 * users, and "new" versus "returned" is exactly the distinction someone
 * triaging needs to read at a glance.
 */
const styles: Record<Status, string> = {
  new: 'bg-blue-500/15 text-blue-700 ring-blue-500/30 dark:text-blue-400',
  open: 'bg-zinc-500/15 text-zinc-600 ring-zinc-500/30 dark:text-zinc-400',
  fixed: 'bg-emerald-600/15 text-emerald-700 ring-emerald-600/30 dark:text-emerald-400',
  regressed: 'bg-purple-600/15 text-purple-700 ring-purple-600/30 dark:text-purple-400',
}

const glyphs: Record<Status, string> = {
  new: '+',
  open: '=',
  fixed: '\u2212',
  regressed: '\u21ba',
}

export function StatusBadge({
  status,
  className,
}: {
  status?: string
  className?: string
}) {
  const normalized = normalizeStatus(status)
  if (!normalized) {
    return null
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset',
        styles[normalized],
        className,
      )}
    >
      <span aria-hidden className="font-mono">
        {glyphs[normalized]}
      </span>
      {STATUS_LABEL[normalized]}
    </span>
  )
}
