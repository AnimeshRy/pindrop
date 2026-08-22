import { createFileRoute, redirect } from '@tanstack/react-router'
import { AlertOctagon, CheckCircle2, ShieldAlert, Sparkles } from 'lucide-react'
import { useEffect, useState } from 'react'

import { AppShell } from '@/components/app-shell'
import { RankedIssues } from '@/components/dashboard/ranked-issues'
import { ScanHistory } from '@/components/dashboard/scan-history'
import { SeverityBreakdown } from '@/components/dashboard/severity-breakdown'
import { StatCard } from '@/components/dashboard/stat-card'
import { ApiError, listRepos, type Repo } from '@/lib/api'
import {
  aggregateSeverity,
  deltaTotals,
  fetchOrgActivity,
  fetchOpenFindings,
  openTotal,
  rankedFindings,
  type RepoActivity,
  type RankedFinding,
} from '@/lib/dashboard'

export const Route = createFileRoute('/dashboard')({
  beforeLoad: ({ context }) => {
    if (context.auth.loading) {
      return
    }
    if (!context.auth.user) {
      throw redirect({ to: '/login' })
    }
  },
  component: DashboardPage,
})

const RANKED_LIMIT = 8

function DashboardPage() {
  const { auth } = Route.useRouteContext()
  const token = auth.session?.access_token

  const [repos, setRepos] = useState<Repo[]>([])
  const [activity, setActivity] = useState<RepoActivity[]>([])
  const [openFindings, setOpenFindings] = useState<RankedFinding[]>([])
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
      .then(async (repoList) => {
        if (cancelled) {
          return
        }
        setRepos(repoList)
        setError(null)
        const [orgActivity, rankedPool] = await Promise.all([
          fetchOrgActivity(token, repoList),
          fetchOpenFindings(token, repoList),
        ])
        if (!cancelled) {
          setActivity(orgActivity)
          setOpenFindings(rankedPool)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(
            err instanceof ApiError ? err.message : 'Could not load your dashboard',
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

  if (loading) {
    return (
      <AppShell>
        <Skeleton />
      </AppShell>
    )
  }

  if (error) {
    return (
      <AppShell>
        <p className="text-sm" style={{ color: 'var(--muted-foreground)' }}>
          {error}
        </p>
      </AppShell>
    )
  }

  if (repos.length === 0) {
    return (
      <AppShell>
        <EmptyState />
      </AppShell>
    )
  }

  const severity = aggregateSeverity(repos)
  const delta = deltaTotals(activity)
  const ranked = rankedFindings(openFindings, RANKED_LIMIT)
  const openCount = openTotal(repos)

  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Security overview</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--muted-foreground)' }}>
            {repos.length} {repos.length === 1 ? 'repository' : 'repositories'} synced
            from the CLI
          </p>
        </div>

        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            label="Open findings"
            value={openCount}
            caption="across all synced repositories"
            icon={ShieldAlert}
          />
          <StatCard
            label="Critical & high"
            value={severity.critical + severity.high}
            caption="need attention first"
            icon={AlertOctagon}
          />
          <StatCard
            label="New since last scan"
            value={delta.new}
            caption="from each repo's latest run"
            icon={Sparkles}
          />
          <StatCard
            label="No longer detected"
            value={delta.fixed}
            caption="from each repo's latest run"
            icon={CheckCircle2}
          />
        </div>

        <SeverityBreakdown counts={severity} />

        <ScanHistory activities={activity} />

        <RankedIssues findings={ranked} />
      </div>
    </AppShell>
  )
}

function Skeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-7 w-56 rounded" style={{ backgroundColor: 'var(--muted)' }} />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="h-24 rounded-xl"
            style={{ backgroundColor: 'var(--muted)' }}
          />
        ))}
      </div>
      <div className="h-40 rounded-xl" style={{ backgroundColor: 'var(--muted)' }} />
      <div className="h-64 rounded-xl" style={{ backgroundColor: 'var(--muted)' }} />
    </div>
  )
}

function EmptyState() {
  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">Security overview</h1>
      <div
        className="mt-6 rounded-xl border border-dashed p-10 text-center"
        style={{ borderColor: 'var(--border)' }}
      >
        <ShieldAlert
          className="mx-auto size-8"
          style={{ color: 'var(--muted-foreground)' }}
          aria-hidden
        />
        <p className="mt-3 text-sm" style={{ color: 'var(--muted-foreground)' }}>
          No scan history synced yet. Sign in on the CLI and run{' '}
          <code
            className="rounded px-1.5 py-0.5 text-xs"
            style={{ backgroundColor: 'var(--muted)' }}
          >
            pindrop sync
          </code>{' '}
          after scanning a project.
        </p>
      </div>
    </div>
  )
}
