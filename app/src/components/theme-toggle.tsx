import { Monitor, Moon, Sun } from 'lucide-react'

import { cn } from '@/lib/utils'
import { type ThemePreference } from '@/lib/theme'
import { useTheme } from '@/lib/theme-context'

const options: { value: ThemePreference; label: string; icon: typeof Sun }[] = [
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'system', label: 'System', icon: Monitor },
]

interface ThemeToggleProps {
  className?: string
}

/** Accessible segmented control for light, dark, and system themes. */
export function ThemeToggle({ className }: ThemeToggleProps) {
  const { preference, setPreference } = useTheme()

  return (
    <div
      role="group"
      aria-label="Color theme"
      className={cn('inline-flex rounded-lg border p-0.5', className)}
      style={{ borderColor: 'var(--border)', backgroundColor: 'var(--muted)' }}
    >
      {options.map(({ value, label, icon: Icon }) => {
        const active = preference === value
        return (
          <button
            key={value}
            type="button"
            aria-pressed={active}
            title={label}
            onClick={() => setPreference(value)}
            className={cn(
              'inline-flex size-8 items-center justify-center rounded-md transition-colors',
              'focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:outline-none',
              active
                ? 'bg-[var(--card)] text-[var(--foreground)] shadow-sm'
                : 'text-[var(--muted-foreground)]',
            )}
          >
            <Icon className="size-4" aria-hidden />
            <span className="sr-only">{label}</span>
          </button>
        )
      })}
    </div>
  )
}
