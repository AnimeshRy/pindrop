import { Link } from '@tanstack/react-router'

import { cn } from '@/lib/utils'

type ButtonVariant = 'primary' | 'secondary' | 'ghost'

interface SharedProps {
  children: React.ReactNode
  className?: string
  variant?: ButtonVariant
}

interface ButtonLinkProps extends SharedProps {
  to: '/' | '/login' | '/dashboard'
}

interface ButtonProps extends SharedProps {
  type?: 'button' | 'submit'
  disabled?: boolean
  onClick?: () => void
}

function variantClasses(variant: ButtonVariant): string {
  switch (variant) {
    case 'primary':
      return 'bg-[var(--accent)] text-[var(--accent-foreground)] hover:bg-[var(--accent-hover)] border-transparent'
    case 'secondary':
      return 'border-[var(--border)] bg-[var(--card)] hover:bg-[var(--muted)]'
    case 'ghost':
      return 'border-transparent hover:bg-[var(--muted)]'
  }
}

const base =
  'inline-flex h-10 items-center justify-center rounded-lg border px-4 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] disabled:cursor-not-allowed disabled:opacity-60'

export function ButtonLink({
  children,
  className,
  to,
  variant = 'primary',
}: ButtonLinkProps) {
  return (
    <Link to={to} className={cn(base, variantClasses(variant), className)}>
      {children}
    </Link>
  )
}

export function Button({
  children,
  className,
  variant = 'primary',
  type = 'button',
  disabled,
  onClick,
}: ButtonProps) {
  return (
    <button
      type={type}
      disabled={disabled}
      onClick={onClick}
      className={cn(base, variantClasses(variant), className)}
    >
      {children}
    </button>
  )
}
