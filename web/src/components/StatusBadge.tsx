import { STATUS_LABEL, type Status } from '@/lib/api'
import { cn } from '@/lib/utils'

/**
 * Lifecycle styling.
 *
 * Each badge carries a glyph as well as a colour, and spells the status out in
 * words. Colour alone would fail for colourblind users and in grayscale, and
 * "new" versus "returned" is exactly the distinction someone triaging needs to
 * read at a glance.
 */
const styles: Record<Status, string> = {
  new: 'bg-blue-500/15 text-blue-700 dark:text-blue-400 ring-blue-500/30',
  open: 'bg-zinc-500/15 text-zinc-600 dark:text-zinc-400 ring-zinc-500/30',
  fixed: 'bg-emerald-600/15 text-emerald-700 dark:text-emerald-400 ring-emerald-600/30',
  regressed: 'bg-purple-600/15 text-purple-700 dark:text-purple-400 ring-purple-600/30',
}

/** A shape per status, so the badges stay distinguishable without colour. */
const glyphs: Record<Status, string> = {
  new: '+',
  open: '=',
  fixed: '−',
  regressed: '↺',
}

/**
 * `fixed` is never shown as "fixed": the API's word is the Go constant's name,
 * but a scanner ceasing to report something is a weaker claim than a fix, and
 * the label has to say only what is actually known.
 */
export function StatusBadge({
  status,
  className,
}: {
  status: Status
  className?: string
}) {
  const label = STATUS_LABEL[status] ?? status

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset',
        styles[status] ?? styles.open,
        className,
      )}
    >
      <span aria-hidden className="font-mono">
        {glyphs[status] ?? '·'}
      </span>
      {label}
    </span>
  )
}
