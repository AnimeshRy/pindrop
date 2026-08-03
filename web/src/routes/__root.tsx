import { createRootRoute, Link, Outlet } from '@tanstack/react-router'

export const Route = createRootRoute({
  component: RootLayout,
  notFoundComponent: NotFound,
})

function RootLayout() {
  return (
    <div className="min-h-full">
      <header className="border-b" style={{ borderColor: 'var(--border)' }}>
        <div className="mx-auto flex max-w-7xl items-center gap-6 px-4 py-3 sm:px-6">
          <Link to="/" className="flex items-center gap-2 font-semibold">
            <span aria-hidden className="inline-block size-2 rounded-full bg-red-500" />
            Pindrop
          </Link>
          <nav className="flex gap-4 text-sm">
            <Link
              to="/"
              className="hover:underline"
              activeProps={{ className: 'font-medium underline' }}
              activeOptions={{ exact: true }}
            >
              Findings
            </Link>
          </nav>
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
