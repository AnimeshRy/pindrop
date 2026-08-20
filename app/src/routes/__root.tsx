import { createRootRouteWithContext, Outlet } from '@tanstack/react-router'
import { Loader2 } from 'lucide-react'

import { AppNotFound } from '@/components/app-shell'
import type { AuthContextValue } from '@/lib/auth'

/** Router context carries auth so `beforeLoad` guards can run without hooks. */
export interface RouterContext {
  auth: AuthContextValue
}

export const Route = createRootRouteWithContext<RouterContext>()({
  component: RootLayout,
  notFoundComponent: AppNotFound,
})

function RootLayout() {
  const { auth } = Route.useRouteContext()

  // Avoid redirecting to /login while the session is still being restored.
  if (auth.loading) {
    return (
      <div className="flex min-h-full items-center justify-center">
        <Loader2
          className="size-6 animate-spin text-[var(--muted-foreground)]"
          aria-hidden
        />
        <span className="sr-only">Loading</span>
      </div>
    )
  }

  return <Outlet />
}
