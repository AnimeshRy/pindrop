import { Link } from '@tanstack/react-router'

import { PindropLogo } from '@/components/pindrop-logo'
import { ThemeToggle } from '@/components/theme-toggle'

/** Constrained shell for authenticated and sign-in-adjacent pages. */
export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-full">
      <header className="border-b" style={{ borderColor: 'var(--border)' }}>
        <div className="mx-auto flex max-w-5xl items-center gap-4 px-4 py-3 sm:px-6">
          <PindropLogo />
          <div className="ml-auto flex items-center gap-3">
            <ThemeToggle />
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-6 sm:px-6">{children}</main>
    </div>
  )
}

export function AppNotFound() {
  return (
    <AppShell>
      <div className="py-16 text-center">
        <h1 className="text-lg font-medium">Page not found</h1>
        <Link to="/" className="mt-2 inline-block text-sm underline">
          Back to home
        </Link>
      </div>
    </AppShell>
  )
}
