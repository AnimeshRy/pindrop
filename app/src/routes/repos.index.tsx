import { createFileRoute, Link, redirect } from '@tanstack/react-router'
import { ChevronRight, FolderGit2, Loader2 } from 'lucide-react'
import { useEffect, useState } from 'react'

import { AppShell } from '@/components/app-shell'
import {
  ApiError,
  listRepos,
  SOURCE_LABEL,
  type Repo,
  type RepoSource,
} from '@/lib/api'
import { formatRelativeTime, repoLocationLabel, repoRemoteLabel } from '@/lib/utils'

export const Route = createFileRoute('/repos/')({
  beforeLoad: ({ context }) => {
    if (context.auth.loading) {
      return
    }
    if (!context.auth.user) {
      throw redirect({ to: '/login' })
    }
  },
  component: ReposIndexPage,
})

function sourceBadges(links: Repo['links']): RepoSource[] {
  const seen = new Set<RepoSource>()
  const out: RepoSource[] = []
  for (const link of links ?? []) {
    if (!seen.has(link.source)) {
      seen.add(link.source)
      out.push(link.source)
    }
  }
  return out
}

function ReposIndexPage() {
  const { auth } = Route.useRouteContext()
  const token = auth.session?.access_token

  const [repos, setRepos] = useState<Repo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // Absent only for an instant while a session is still being established;
    // the route guard above ensures a signed-in user (and thus a token)
    // before this component ever mounts.
    if (!token) {
      return
    }

    let cancelled = false

    void listRepos(token)
      .then((data) => {
        if (!cancelled) {
          setRepos(data)
          setError(null)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(
            err instanceof ApiError ? err.message : 'Could not load repositories',
          )
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
  }, [token])

  return (
    <AppShell>
      <div className="space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Repositories</h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--muted-foreground)' }}>
              Run{' '}
              <code
                className="rounded px-1.5 py-0.5 text-xs"
                style={{ backgroundColor: 'var(--muted)' }}
              >
                pindrop sync
              </code>{' '}
              locally to push scan history here.
            </p>
          </div>
          <span className="text-sm" style={{ color: 'var(--muted-foreground)' }}>
            {repos.length} synced
          </span>
        </div>

        {loading ? (
          <div
            className="flex items-center gap-2 py-8 text-sm"
            style={{ color: 'var(--muted-foreground)' }}
          >
            <Loader2 className="size-4 animate-spin" aria-hidden />
            Loading repositories…
          </div>
        ) : error ? (
          <div
            className="rounded-xl border border-dashed p-6 text-sm"
            style={{ borderColor: 'var(--border)', color: 'var(--muted-foreground)' }}
          >
            {error}
          </div>
        ) : repos.length === 0 ? (
          <div
            className="rounded-xl border border-dashed p-8 text-center"
            style={{ borderColor: 'var(--border)' }}
          >
            <FolderGit2
              className="mx-auto size-8"
              style={{ color: 'var(--muted-foreground)' }}
              aria-hidden
            />
            <p className="mt-3 text-sm" style={{ color: 'var(--muted-foreground)' }}>
              No scan history synced yet.
            </p>
          </div>
        ) : (
          <ul
            className="divide-y rounded-xl border"
            style={{ borderColor: 'var(--border)' }}
          >
            {repos.map((repo) => {
              const remote = repoRemoteLabel(repo)
              return (
              <li key={repo.id}>
                <Link
                  to="/repos/$repoId"
                  params={{ repoId: repo.id }}
                  className="flex items-center gap-4 px-4 py-4 transition-colors hover:bg-[var(--muted)]/40"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="truncate font-medium">{repo.name}</p>
                      {sourceBadges(repo.links).map((source) => (
                        <span
                          key={source}
                          className="rounded-full border px-2 py-0.5 text-xs"
                          style={{
                            borderColor: 'var(--border)',
                            color: 'var(--muted-foreground)',
                          }}
                        >
                          {SOURCE_LABEL[source]}
                        </span>
                      ))}
                    </div>
                    <p
                      className="mt-1 truncate text-sm"
                      style={{ color: 'var(--muted-foreground)' }}
                    >
                      {repoLocationLabel(repo)}
                      {remote ? (
                        <span className="text-xs"> · {remote}</span>
                      ) : null}
                    </p>
                    <p
                      className="mt-1 text-xs"
                      style={{ color: 'var(--muted-foreground)' }}
                    >
                      Last synced {formatRelativeTime(repo.lastSyncedAt)} ·{' '}
                      {repo.runs ?? 0} runs · {repo.open?.total ?? 0} open
                    </p>
                  </div>
                  <ChevronRight
                    className="size-4 shrink-0"
                    style={{ color: 'var(--muted-foreground)' }}
                    aria-hidden
                  />
                </Link>
              </li>
              )
            })}
          </ul>
        )}
      </div>
    </AppShell>
  )
}
