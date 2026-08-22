import { ChevronLeft, ChevronRight } from 'lucide-react'

import { cn } from '@/lib/utils'

const PAGE_SIZES = [25, 50, 100] as const

/**
 * Simple prev/next pager driven by offset/limit and a server total.
 * Keeps page size selectable so large runs stay manageable.
 */
export function Pagination({
  total,
  limit,
  offset,
  onOffsetChange,
  onLimitChange,
  className,
}: {
  total: number
  limit: number
  offset: number
  onOffsetChange: (offset: number) => void
  onLimitChange: (limit: number) => void
  className?: string
}) {
  if (total === 0) {
    return null
  }

  const pageStart = offset + 1
  const pageEnd = Math.min(offset + limit, total)
  const hasPrev = offset > 0
  const hasNext = offset + limit < total

  return (
    <div
      className={cn(
        'flex flex-wrap items-center justify-between gap-3 text-sm',
        className,
      )}
    >
      <p style={{ color: 'var(--muted-foreground)' }}>
        Showing {pageStart}–{pageEnd} of {total}
      </p>

      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-xs" style={{ color: 'var(--muted-foreground)' }}>
          Per page
          <select
            value={limit}
            onChange={(event) => onLimitChange(Number(event.target.value))}
            className="rounded-md border px-2 py-1 text-sm"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
          >
            {PAGE_SIZES.map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
        </label>

        <div className="flex items-center gap-1">
          <button
            type="button"
            disabled={!hasPrev}
            onClick={() => onOffsetChange(Math.max(0, offset - limit))}
            className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1.5 text-xs transition-colors hover:bg-[var(--muted)] disabled:cursor-not-allowed disabled:opacity-50"
            style={{ borderColor: 'var(--border)' }}
          >
            <ChevronLeft className="size-3.5" aria-hidden />
            Previous
          </button>
          <button
            type="button"
            disabled={!hasNext}
            onClick={() => onOffsetChange(offset + limit)}
            className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1.5 text-xs transition-colors hover:bg-[var(--muted)] disabled:cursor-not-allowed disabled:opacity-50"
            style={{ borderColor: 'var(--border)' }}
          >
            Next
            <ChevronRight className="size-3.5" aria-hidden />
          </button>
        </div>
      </div>
    </div>
  )
}
