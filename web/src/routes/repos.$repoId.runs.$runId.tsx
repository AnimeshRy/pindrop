import { useQuery } from '@tanstack/react-query'
import { createFileRoute, Link } from '@tanstack/react-router'
import { useState } from 'react'

import { DeltaBadges } from '@/components/DeltaBadges'
import { FindingsTable } from '@/components/FindingsTable'
import { SummaryTiles } from '@/components/SummaryTiles'
import { fetchRun, fetchRunFindings, type Summary } from '@/lib/api'
import { cn, formatAbsolute, formatRelative, shortCommit } from '@/lib/utils'

export const Route = createFileRoute('/repos/$repoId/runs/$runId')({
  component: RunPage,
})

/** Which findings the table shows. */
type Scope = 'all' | 'new'

function RunPage() {
  const { repoId, runId } = Route.useParams()
  const [scope, setScope] = useState<Scope>('all')

  const run = useQuery({
    queryKey: ['run', repoId, runId],
    queryFn: () => fetchRun(repoId, runId),
  })
  const findings = useQuery({
    queryKey: ['run-findings', repoId, runId],
    queryFn: () => fetchRunFindings(repoId, runId),
  })

  if (run.isPending || findings.isPending) {
    return <Skeleton />
  }

  const error = run.error ?? findings.error
  if (error) {
    return (
      <div
        className="rounded-lg border p-6"
        style={{ borderColor: 'var(--border)', background: 'var(--card)' }}
      >
        <h2 className="font-medium">Could not load this run</h2>
        <p className="mt-2 text-sm" style={{ color: 'var(--muted-foreground)' }}>
          {error.message}
        </p>
        <Link
          to="/repos/$repoId"
          params={{ repoId }}
          className="mt-4 inline-block text-sm underline"
        >
          Back to the run timeline
        </Link>
      </div>
    )
  }

  const detail = run.data
  const rows = findings.data ?? []
  // "New only" means new *and* returned: both are findings that were not open
  // in the previous run, which is the question someone triaging is asking.
  const shown =
    scope === 'new'
      ? rows.filter((f) => f.status === 'new' || f.status === 'regressed')
      : rows

  // SummaryTiles takes the single-report Summary shape; a run carries the same
  // counts under a different name, so it is adapted here rather than the tile
  // component growing a second input type.
  const summary: Summary | undefined = detail && {
    total: detail.summary.total,
    bySeverity: detail.summary.bySeverity,
    byCategory: detail.summary.byCategory,
    scans: detail.run.scanners ?? [],
    generatedAt: detail.run.finishedAt,
  }

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/repos/$repoId"
          params={{ repoId }}
          className="text-xs hover:underline"
          style={{ color: 'var(--muted-foreground)' }}
        >
          ← Run timeline
        </Link>
        <h1 className="mt-1 text-xl font-semibold">
          {detail && (
            <span title={formatAbsolute(detail.run.finishedAt)}>
              Scan {formatRelative(detail.run.finishedAt)}
            </span>
          )}
        </h1>
        {detail && (
          <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-2 text-sm">
            <code className="font-mono text-xs" style={{ color: 'var(--muted-foreground)' }}>
              {detail.run.vcs?.branch ?? 'no branch'}
              {detail.run.vcs?.commit ? ` @ ${shortCommit(detail.run.vcs.commit)}` : ''}
            </code>
            <DeltaBadges delta={detail.run.delta} />
          </div>
        )}
      </div>

      {summary && <SummaryTiles summary={summary} />}

      <div className="flex items-center gap-2">
        <span className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
          Show
        </span>
        {(
          [
            ['all', `all (${rows.length})`],
            [
              'new',
              `new or returned (${rows.filter((f) => f.status === 'new' || f.status === 'regressed').length})`,
            ],
          ] as ReadonlyArray<[Scope, string]>
        ).map(([value, label]) => (
          <button
            key={value}
            type="button"
            onClick={() => setScope(value)}
            aria-pressed={scope === value}
            className={cn(
              'rounded-md border px-2.5 py-1 text-xs',
              scope === value && 'font-medium underline',
            )}
            style={{
              borderColor: 'var(--border)',
              background: scope === value ? 'var(--muted)' : 'var(--card)',
            }}
          >
            {label}
          </button>
        ))}
      </div>

      <FindingsTable findings={shown} />
    </div>
  )
}

function Skeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-6 w-48 rounded" style={{ background: 'var(--muted)' }} />
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {Array.from({ length: 6 }, (_, i) => (
          <div key={i} className="h-20 rounded-lg" style={{ background: 'var(--muted)' }} />
        ))}
      </div>
      <div className="h-64 rounded-lg" style={{ background: 'var(--muted)' }} />
    </div>
  )
}
