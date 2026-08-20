import { createRouter, RouterProvider } from '@tanstack/react-router'
import { StrictMode, useEffect } from 'react'
import { createRoot } from 'react-dom/client'

import { AuthProvider, useAuth } from '@/lib/auth'
import { ThemeProvider } from '@/lib/theme-provider'
import './index.css'
import { routeTree } from './routeTree.gen'

const router = createRouter({
  routeTree,
  context: {
    // Populated by AppShell before the first navigation guard runs.
    auth: undefined!,
  },
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}

/**
 * Bridges React auth state into TanStack Router context and re-runs route
 * guards once the initial Supabase session has been restored.
 */
function AppShell() {
  const auth = useAuth()

  useEffect(() => {
    if (!auth.loading) {
      void router.invalidate()
    }
  }, [auth.loading, auth.user])

  return <RouterProvider router={router} context={{ auth }} />
}

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('root element not found')
}

createRoot(rootElement).render(
  <StrictMode>
    <ThemeProvider>
      <AuthProvider>
        <AppShell />
      </AuthProvider>
    </ThemeProvider>
  </StrictMode>,
)
