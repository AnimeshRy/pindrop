import { createFileRoute, Link } from '@tanstack/react-router'
import { ArrowLeft, Loader2 } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'

import { AppShell } from '@/components/app-shell'
import { DeltaBadges } from '@/components/delta-badges'
import { FindingsTable } from '@/components/findings-table'
import { SummaryTiles } from '@/components/summary-tiles'
import {
  ApiError,
  getRun,
  listRunFindings,
  type Finding,
  type FindingListParams,
  type Run,
} from '@/lib/api'
import { formatAbsoluteTime, formatRelativeTime, shortCommit } from '@/lib/utils'

export const Route = createFileRoute('/repos/$repoId/runs/$runId')({
  component: RunDetailPage,
})

function RunDetailPage() {
  const { auth } = Route.useRouteContext()
  const { repoId, runId } = Route.useParams()
  const token = auth.session?.access_token

  const [run, setRun] = useState<Run | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [total, setTotal] = useState(0)
  const [params, setParams] = useState<FindingListParams>({ limit: 50, offset: 0 })
  const [runLoadedFor, setRunLoadedFor] = useState<string | null>(null)
  const [findingsLoadedKey, setFindingsLoadedKey] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const findingsKey = JSON.stringify({ repoId, runId, params })
  const loadingRun = runLoadedFor !== runId
  const loadingFindings = findingsLoadedKey !== findingsKey

  useEffect(() => {
    if (!token) {
      return
    }

    let cancelled = false

    void getRun(token, repoId, runId)
      .then((data) => {
        if (!cancelled) {
          setRun(data)
          setError(null)
          setRunLoadedFor(runId)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.message : 'Could not load scan run')
          setRunLoadedFor(runId)
        }
      })

    return () => {
      cancelled = true
    }
  }, [token, repoId, runId])

  useEffect(() => {
    if (!token) {
      return
    }

    let cancelled = false

    void listRunFindings(token, repoId, runId, params)
      .then((data) => {
        if (!cancelled) {
          setFindings(data.findings)
          setTotal(data.total)
          setFindingsLoadedKey(findingsKey)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setFindings([])
          setTotal(0)
          setFindingsLoadedKey(findingsKey)
        }
      })

    return () => {
      cancelled = true
    }
  }, [token, repoId, runId, params, findingsKey])

  const handleParamsChange = useCallback((patch: Partial<FindingListParams>) => {
    setParams((prev) => ({ ...prev, ...patch }))
  }, [])

  if (loadingRun) {
    return (
      <AppShell>
        <div className="flex items-center gap-2 py-16 text-sm text-[var(--muted-foreground)]">
          <Loader2 className="size-4 animate-spin" aria-hidden />
          Loading scan run…
        </div>
      </AppShell>
    )
  }

  if (error || !run) {
    return (
      <AppShell>
        <Link
          to="/repos/$repoId"
          params={{ repoId }}
          className="inline-flex items-center gap-2 text-sm text-[var(--muted-foreground)] hover:underline"
        >
          <ArrowLeft className="size-4" aria-hidden />
          Back to repository
        </Link>
        <p className="mt-6 text-sm text-[var(--muted-foreground)]">
          {error ?? 'Scan run not found'}
        </p>
      </AppShell>
    )
  }

  return (
    <AppShell>
      <div className="space-y-6">
        <Link
          to="/repos/$repoId"
          params={{ repoId }}
          className="inline-flex items-center gap-2 text-sm text-[var(--muted-foreground)] hover:underline"
        >
          <ArrowLeft className="size-4" aria-hidden />
          Back to repository
        </Link>

        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            <span title={formatAbsoluteTime(run.finishedAt)}>
              Scan {formatRelativeTime(run.finishedAt)}
            </span>
          </h1>
          <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-2 text-sm">
            <code
              className="font-mono text-xs"
              style={{ color: 'var(--muted-foreground)' }}
            >
              {run.vcs?.branch ?? 'no branch'}
              {run.vcs?.commit ? ` @ ${shortCommit(run.vcs.commit)}` : ''}
            </code>
            <DeltaBadges delta={run.delta} />
          </div>
        </div>

        <SummaryTiles counts={run.counts} />

        <section
          className="rounded-xl border p-4"
          style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
        >
          <h2 className="text-sm font-medium">Findings</h2>
          <div className="mt-4">
            <FindingsTable
              findings={findings}
              total={total}
              params={params}
              loading={loadingFindings}
              onParamsChange={handleParamsChange}
            />
          </div>
        </section>
      </div>
    </AppShell>
  )
}
