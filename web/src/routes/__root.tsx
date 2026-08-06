import { createRootRoute, Link, Outlet, redirect } from '@tanstack/react-router'

import { UserMenu } from '@/components/UserMenu'
import { waitForInitialSession } from '@/lib/auth-bootstrap'
import { getAppConfig, isCloudMode } from '@/lib/config'

export const Route = createRootRoute({
  beforeLoad: async ({ location }) => {
    if (!isCloudMode()) {
      return
    }

    const session = await waitForInitialSession()
    const path = location.pathname
    const isPublicAuth = path === '/login' || path.startsWith('/auth/')

    if (!session && !isPublicAuth) {
      throw redirect({ to: '/login' })
    }
    if (session && path === '/login') {
      throw redirect({ to: '/' })
    }
  },
  component: RootLayout,
  notFoundComponent: NotFound,
})

function RootLayout() {
  const config = getAppConfig()

  return (
    <div className="min-h-full">
      <header className="border-b" style={{ borderColor: 'var(--border)' }}>
        <div className="mx-auto flex max-w-7xl items-center gap-6 px-4 py-3 sm:px-6">
          <Link to="/" className="flex items-center gap-2 font-semibold">
            <span aria-hidden className="inline-block size-2 rounded-full bg-red-500" />
            Pindrop
          </Link>
          <nav className="flex flex-1 gap-4 text-sm">
            <Link
              to="/"
              className="hover:underline"
              activeProps={{ className: 'font-medium underline' }}
              activeOptions={{ exact: true }}
            >
              Findings
            </Link>
          </nav>
          {config.mode === 'cloud' && <UserMenu />}
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
        <Outlet />
      </main>
    </div>
  )
}

function NotFound() {
  return (
    <div className="py-16 text-center">
      <h1 className="text-lg font-medium">Page not found</h1>
      <Link to="/" className="mt-2 inline-block text-sm underline">
        Back to findings
      </Link>
    </div>
  )
}
