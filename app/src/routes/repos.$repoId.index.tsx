import { createFileRoute, Link } from '@tanstack/react-router'
import { ArrowLeft, ChevronRight, Loader2 } from 'lucide-react'
import { useEffect, useState } from 'react'

import { AppShell } from '@/components/app-shell'
import { DeltaBadges } from '@/components/delta-badges'
import {
  ApiError,
  getRepo,
  listRuns,
  SOURCE_LABEL,
  type Repo,
  type Run,
} from '@/lib/api'
import { formatRelativeTime, repoLocationLabel, repoRemoteLabel } from '@/lib/utils'

export const Route = createFileRoute('/repos/$repoId/')({
  component: RepoDetailPage,
})

function RepoDetailPage() {
  const { auth } = Route.useRouteContext()
  const { repoId } = Route.useParams()
  const token = auth.session?.access_token

  const [repo, setRepo] = useState<Repo | null>(null)
  const [runs, setRuns] = useState<Run[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!token) {
      return
    }

    let cancelled = false

    void Promise.all([getRepo(token, repoId), listRuns(token, repoId)])
      .then(([repoData, runData]) => {
        if (!cancelled) {
          setRepo(repoData)
          setRuns(runData)
          setError(null)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.message : 'Could not load repository')
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [token, repoId])

  if (loading) {
    return (
      <AppShell>
        <div className="flex items-center gap-2 py-16 text-sm text-[var(--muted-foreground)]">
          <Loader2 className="size-4 animate-spin" aria-hidden />
          Loading repository…
        </div>
      </AppShell>
    )
  }

  if (error || !repo) {
    return (
      <AppShell>
        <Link
          to="/dashboard"
          className="inline-flex items-center gap-2 text-sm text-[var(--muted-foreground)] hover:underline"
        >
          <ArrowLeft className="size-4" aria-hidden />
          Back to dashboard
        </Link>
        <p className="mt-6 text-sm text-[var(--muted-foreground)]">
          {error ?? 'Repository not found'}
        </p>
      </AppShell>
    )
  }

  return (
    <AppShell>
      <div className="space-y-6">
        <Link
          to="/dashboard"
          className="inline-flex items-center gap-2 text-sm text-[var(--muted-foreground)] hover:underline"
        >
          <ArrowLeft className="size-4" aria-hidden />
          Back to dashboard
        </Link>

        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{repo.name}</h1>
          <p className="mt-1 text-sm text-[var(--muted-foreground)]">
            {repoLocationLabel(repo)}
            {repoRemoteLabel(repo) ? <> · {repoRemoteLabel(repo)}</> : null} · Last synced{' '}
            {formatRelativeTime(repo.lastSyncedAt)} · {repo.open?.total ?? 0} open
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            {(repo.links ?? []).map((link) => (
              <span
                key={link.id}
                className="rounded-full border px-2 py-0.5 text-xs text-[var(--muted-foreground)]"
                style={{ borderColor: 'var(--border)' }}
              >
                {SOURCE_LABEL[link.source]}
                {link.path ? ` · ${link.path}` : ''}
              </span>
            ))}
          </div>
        </div>

        <section
          className="rounded-xl border"
          style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
        >
          <h2
            className="border-b px-4 py-3 text-sm font-medium"
            style={{ borderColor: 'var(--border)' }}
          >
            Scan runs
          </h2>
          {runs.length === 0 ? (
            <p className="p-4 text-sm text-[var(--muted-foreground)]">
              No runs synced yet.
            </p>
          ) : (
            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {runs.map((run) => (
                <li key={run.id}>
                  <Link
                    to="/repos/$repoId/runs/$runId"
                    params={{ repoId, runId: run.id }}
                    className="flex items-center gap-4 px-4 py-3 transition-colors hover:bg-[var(--muted)]/40"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium">
                        {formatRelativeTime(run.finishedAt)}
                      </p>
                      <p className="mt-1 text-xs text-[var(--muted-foreground)]">
                        {run.counts.total} findings
                        {run.vcs?.branch ? ` · ${run.vcs.branch}` : ''}
                        {run.vcs?.commit ? ` @ ${run.vcs.commit.slice(0, 7)}` : ''}
                      </p>
                      <div className="mt-1.5">
                        <DeltaBadges delta={run.delta} />
                      </div>
                    </div>
                    <ChevronRight
                      className="size-4 shrink-0"
                      style={{ color: 'var(--muted-foreground)' }}
                      aria-hidden
                    />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </AppShell>
  )
}
