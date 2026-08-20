import { Link } from '@tanstack/react-router'

import { cn } from '@/lib/utils'

interface PindropLogoProps {
  className?: string
  /** When set, the mark links to this route. Omit for static branding. */
  to?: '/' | '/dashboard'
}

/** Minimal wordmark with a small accent dot. */
export function PindropLogo({ className, to = '/' }: PindropLogoProps) {
  const content = (
    <>
      <span
        aria-hidden
        className="inline-block size-2 rounded-full bg-[var(--accent)]"
      />
      <span className="text-base font-semibold tracking-tight">Pindrop</span>
    </>
  )

  if (to) {
    return (
      <Link
        to={to}
        className={cn(
          'inline-flex items-center gap-2 focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:outline-none',
          className,
        )}
      >
        {content}
      </Link>
    )
  }

  return (
    <span className={cn('inline-flex items-center gap-2', className)}>{content}</span>
  )
}
