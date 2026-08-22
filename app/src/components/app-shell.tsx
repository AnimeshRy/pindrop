import { Link } from '@tanstack/react-router'

import { AppSidebar } from '@/components/app-sidebar'
import { PindropLogo } from '@/components/pindrop-logo'
import { ThemeToggle } from '@/components/theme-toggle'

/** Sidebar + top bar shell for authenticated pages. */
export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen">
      <AppSidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <header
          className="flex h-14 shrink-0 items-center justify-end gap-3 border-b px-4 sm:px-6"
          style={{ borderColor: 'var(--border)' }}
        >
          <ThemeToggle />
        </header>
        <main className="min-w-0 flex-1 overflow-y-auto px-4 py-6 sm:px-6">
          {children}
        </main>
      </div>
    </div>
  )
}

/** Unauthenticated pages (login, 404) get the plain header, no sidebar. */
export function AppNotFound() {
  return (
    <div className="min-h-full">
      <header className="border-b" style={{ borderColor: 'var(--border)' }}>
        <div className="mx-auto flex max-w-5xl items-center gap-4 px-4 py-3 sm:px-6">
          <PindropLogo />
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-16 text-center sm:px-6">
        <h1 className="text-lg font-medium">Page not found</h1>
        <Link to="/" className="mt-2 inline-block text-sm underline">
          Back to home
        </Link>
      </main>
    </div>
  )
}
