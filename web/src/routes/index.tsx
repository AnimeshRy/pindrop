import { useQueries, useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'

import { RepoTable } from '@/components/RepoTable'
import { SingleReport } from '@/components/SingleReport'
import { ApiError, fetchRepos, fetchRuns, type DeltaCounts } from '@/lib/api'

export const Route = createFileRoute('/')({
  component: ReposPage,
})

function ReposPage() {
  const repos = useQuery({ queryKey: ['repos'], queryFn: fetchRepos })

  // The repository summary carries current open counts but not what the last
  // run changed, which lives on the run. One extra request per repository is
  // cheap against a local store and keeps the API's repo record from growing a
  // denormalized copy that could disagree with the run.
  const lastRuns = useQueries({
    queries: (repos.data ?? []).map((repo) => ({
      queryKey: ['runs', repo.id, { limit: 1 }],
      queryFn: () => fetchRuns(repo.id, { limit: 1 }),
    })),
  })

  const deltas: Record<string, DeltaCounts | undefined> = {}
  ;(repos.data ?? []).forEach((repo, index) => {
    deltas[repo.id] = lastRuns[index]?.data?.runs[0]?.delta
  })

  if (repos.isPending) {
    return <Skeleton />
  }
  // A 404 here means the server was started with --results and has no history
  // at all. That mode's landing page is the single report it was given, exactly
  // as it was before scan history existed.
  if (repos.error instanceof ApiError && repos.error.status === 404) {
    return <SingleReport />
  }
  if (repos.error) {
    return <ErrorState error={repos.error} />
  }
  if (!repos.data || repos.data.length === 0) {
    return <EmptyState />
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Repositories</h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--muted-foreground)' }}>
          {repos.data.length} {repos.data.length === 1 ? 'repository' : 'repositories'} with
          recorded scans
        </p>
      </div>

      <RepoTable repos={repos.data} deltas={deltas} />
    </div>
  )
}

function Skeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-6 w-40 rounded" style={{ background: 'var(--muted)' }} />
      <div className="h-64 rounded-lg" style={{ background: 'var(--muted)' }} />
    </div>
  )
}

/**
 * An empty store is the first-run state, not a failure. It is by far the most
 * likely reason this page is blank, so it gets the command rather than an
 * apology.
 */
function EmptyState() {
  return (
    <div
      className="rounded-lg border p-6"
      style={{ borderColor: 'var(--border)', background: 'var(--card)' }}
    >
      <h2 className="font-medium">No scans recorded yet</h2>
      <p className="mt-2 text-sm" style={{ color: 'var(--muted-foreground)' }}>
        Scan a project and Pindrop will record it here, so the next scan can tell you what
        changed.
      </p>
      <pre
        className="mt-4 overflow-x-auto rounded-md p-3 text-xs"
        style={{ background: 'var(--muted)' }}
      >
        pindrop scan .
      </pre>
    </div>
  )
}

function ErrorState({ error }: { error: Error }) {
  return (
    <div
      className="rounded-lg border p-6"
      style={{ borderColor: 'var(--border)', background: 'var(--card)' }}
    >
      <h2 className="font-medium">Could not load scan history</h2>
      <p className="mt-2 text-sm" style={{ color: 'var(--muted-foreground)' }}>
        {error.message}
      </p>
    </div>
  )
}
