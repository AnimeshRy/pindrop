import { useQuery } from '@tanstack/react-query'
import { createFileRoute, Link } from '@tanstack/react-router'

import { RunTimeline } from '@/components/RunTimeline'
import { fetchRepo, fetchRuns } from '@/lib/api'
import { formatAbsolute, formatRelative } from '@/lib/utils'

export const Route = createFileRoute('/repos/$repoId/')({
  component: RepoPage,
})

/** How many runs to show before offering the next page. */
const PAGE_SIZE = 50

function RepoPage() {
  const { repoId } = Route.useParams()

  const repo = useQuery({
    queryKey: ['repo', repoId],
    queryFn: () => fetchRepo(repoId),
  })
  const runs = useQuery({
    queryKey: ['runs', repoId, { limit: PAGE_SIZE }],
    queryFn: () => fetchRuns(repoId, { limit: PAGE_SIZE }),
  })

  if (repo.isPending || runs.isPending) {
    return <Skeleton />
  }

  const error = repo.error ?? runs.error
  if (error) {
    return (
      <div
        className="rounded-lg border p-6"
        style={{ borderColor: 'var(--border)', background: 'var(--card)' }}
      >
        <h2 className="font-medium">Could not load this repository</h2>
        <p className="mt-2 text-sm" style={{ color: 'var(--muted-foreground)' }}>
          {error.message}
        </p>
        <Link to="/" className="mt-4 inline-block text-sm underline">
          Back to repositories
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/"
          className="text-xs hover:underline"
          style={{ color: 'var(--muted-foreground)' }}
        >
          ← Repositories
        </Link>
        <h1 className="mt-1 text-xl font-semibold">{repo.data?.name}</h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--muted-foreground)' }}>
          <code className="font-mono text-xs">{repo.data?.path}</code>
          {repo.data && (
            <>
              {' · '}
              {repo.data.runs} {repo.data.runs === 1 ? 'run' : 'runs'}
              {' · '}
              <span title={formatAbsolute(repo.data.lastRunAt)}>
                last scanned {formatRelative(repo.data.lastRunAt)}
              </span>
            </>
          )}
        </p>
        {repo.data?.missing && (
          <p className="mt-2 text-sm text-amber-700 dark:text-amber-400">
            ⚠ This checkout is no longer on disk, so no new runs will arrive. The
            recorded history below is still complete.
          </p>
        )}
      </div>

      {runs.data && <RunTimeline repoId={repoId} runs={runs.data.runs} />}

      {runs.data?.nextBefore && (
        <p className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
          Showing the most recent {runs.data.runs.length} runs.
        </p>
      )}
    </div>
  )
}

function Skeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-6 w-48 rounded" style={{ background: 'var(--muted)' }} />
      <div className="h-64 rounded-lg" style={{ background: 'var(--muted)' }} />
    </div>
  )
}
