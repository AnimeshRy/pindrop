import type { LucideIcon } from 'lucide-react'

/** One top-level metric tile, with a one-line caption so a number is never bare. */
export function StatCard({
  label,
  value,
  caption,
  icon: Icon,
}: {
  label: string
  value: number
  caption: string
  icon: LucideIcon
}) {
  return (
    <div
      className="rounded-xl border p-4"
      style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
    >
      <div className="flex items-center justify-between">
        <p className="text-sm" style={{ color: 'var(--muted-foreground)' }}>
          {label}
        </p>
        <Icon
          className="size-4"
          style={{ color: 'var(--muted-foreground)' }}
          aria-hidden
        />
      </div>
      <p className="mt-2 text-2xl font-semibold tabular-nums">{value}</p>
      <p className="mt-1 text-xs" style={{ color: 'var(--muted-foreground)' }}>
        {caption}
      </p>
    </div>
  )
}
