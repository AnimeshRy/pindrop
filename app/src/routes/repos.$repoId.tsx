import { createFileRoute, Outlet, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/repos/$repoId')({
  beforeLoad: ({ context }) => {
    if (context.auth.loading) {
      return
    }
    if (!context.auth.user) {
      throw redirect({ to: '/login' })
    }
  },
  component: RepoLayout,
})

/**
 * Parent layout for repository pages.
 * Run detail lives at /repos/$repoId/runs/$runId and mounts through Outlet.
 */
function RepoLayout() {
  return <Outlet />
}
