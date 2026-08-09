import { createFileRoute, Outlet } from '@tanstack/react-router'

export const Route = createFileRoute('/repos/$repoId')({
  component: RepoLayout,
})

/**
 * Parent layout for a repository's pages.
 *
 * Run detail is a child route; without an Outlet here, navigation to
 * /repos/$repoId/runs/$runId updates the URL but never mounts the run view.
 */
function RepoLayout() {
  return <Outlet />
}
