import { Link, useNavigate } from '@tanstack/react-router'

import { DeltaBadges } from '@/components/DeltaBadges'
import type { Run } from '@/lib/api'
import { formatAbsolute, formatRelative, shortCommit } from '@/lib/utils'

/**
 * A repository's runs, newest first.
 *
 * This is a list rather than a table because the ordering is the content: runs
 * are read as a sequence, and sorting them any other way would destroy the one
 * thing they are for. The authoritative order comes from the API, which links
 * each run to its predecessor; nothing here re-sorts by ID.
 */
export function RunTimeline({ repoId, runs }: { repoId: string; runs: Run[] }) {
  const navigate = useNavigate()

  if (runs.length === 0) {
    return (
      <p className="text-sm" style={{ color: 'var(--muted-foreground)' }}>
        No runs recorded for this repository yet.
      </p>
    )
  }

  return (
    <ol className="rounded-lg border" style={{ borderColor: 'var(--border)' }}>
      {runs.map((run, index) => (
        <li
          key={run.id}
          onClick={() =>
            void navigate({
              to: '/repos/$repoId/runs/$runId',
              params: { repoId, runId: run.id },
            })
          }
          className="flex cursor-pointer flex-wrap items-baseline gap-x-4 gap-y-2 px-4 py-3 hover:bg-black/[0.02] dark:hover:bg-white/[0.03]"
          style={{
            borderTop: index === 0 ? undefined : '1px solid var(--border)',
          }}
        >
          <Link
            to="/repos/$repoId/runs/$runId"
            params={{ repoId, runId: run.id }}
            className="text-sm font-medium hover:underline"
            title={formatAbsolute(run.finishedAt)}
          >
            {formatRelative(run.finishedAt)}
          </Link>

          <span
            className="font-mono text-xs whitespace-nowrap"
            style={{ color: 'var(--muted-foreground)' }}
          >
            {run.vcs?.branch ?? 'no branch'}
            {run.vcs?.commit ? ` @ ${shortCommit(run.vcs.commit)}` : ''}
          </span>

          <span
            className="text-xs tabular-nums"
            style={{ color: 'var(--muted-foreground)' }}
          >
            {run.counts.total} {run.counts.total === 1 ? 'finding' : 'findings'}
          </span>

          {run.unreadable ? (
            // A stored result quietly disappearing is worse than a broken row,
            // so an unreadable run stays listed and says why.
            <span
              className="text-xs font-medium text-amber-700 dark:text-amber-400"
              title={run.problem}
            >
              ⚠ unreadable — {run.problem ?? 'this run could not be decoded'}
            </span>
          ) : (
            <DeltaBadges delta={run.delta} className="ml-auto" />
          )}
        </li>
      ))}
    </ol>
  )
}
