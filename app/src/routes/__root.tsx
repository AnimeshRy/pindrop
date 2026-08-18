import { createRootRouteWithContext, Link, Outlet } from '@tanstack/react-router'
import { Loader2 } from 'lucide-react'

import type { AuthContextValue } from '@/lib/auth'

/** Router context carries auth so `beforeLoad` guards can run without hooks. */
export interface RouterContext {
  auth: AuthContextValue
}

export const Route = createRootRouteWithContext<RouterContext>()({
  component: RootLayout,
  notFoundComponent: NotFound,
})

function RootLayout() {
  const { auth } = Route.useRouteContext()

  // Avoid redirecting to /login while the session is still being restored.
  if (auth.loading) {
    return (
      <div className="flex min-h-full items-center justify-center">
        <Loader2 className="size-6 animate-spin text-[var(--muted-foreground)]" />
        <span className="sr-only">Loading</span>
      </div>
    )
  }

  return (
    <div className="min-h-full">
      <header className="border-b" style={{ borderColor: 'var(--border)' }}>
        <div className="mx-auto flex max-w-5xl items-center gap-6 px-4 py-3 sm:px-6">
          <Link to="/dashboard" className="flex items-center gap-2 font-semibold">
            <span aria-hidden className="inline-block size-2 rounded-full bg-red-500" />
            Pindrop
          </Link>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-4 py-6 sm:px-6">
        <Outlet />
      </main>
    </div>
  )
}

function NotFound() {
  return (
    <div className="py-16 text-center">
      <h1 className="text-lg font-medium">Page not found</h1>
      <Link to="/dashboard" className="mt-2 inline-block text-sm underline">
        Back to dashboard
      </Link>
    </div>
  )
}
