import { Link } from '@tanstack/react-router'

import { DeltaBadges } from '@/components/delta-badges'
import type { RepoActivity } from '@/lib/dashboard'
import { formatRelativeTime } from '@/lib/utils'

/**
 * Latest scan per synced repository, newest first.
 * Reuses dashboard activity data — no extra API round trip.
 */
export function ScanHistory({ activities }: { activities: RepoActivity[] }) {
  const rows = activities
    .filter((activity) => activity.latestRun)
    .sort(
      (a, b) =>
        new Date(b.latestRun!.finishedAt).getTime() -
        new Date(a.latestRun!.finishedAt).getTime(),
    )

  return (
    <div
      className="rounded-xl border"
      style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
    >
      <div className="border-b px-4 py-3" style={{ borderColor: 'var(--border)' }}>
        <h2 className="text-sm font-medium">Scan history</h2>
        <p className="mt-0.5 text-xs" style={{ color: 'var(--muted-foreground)' }}>
          Latest synced run from each repository
        </p>
      </div>

      {rows.length === 0 ? (
        <p className="p-4 text-sm" style={{ color: 'var(--muted-foreground)' }}>
          No scan runs synced yet.
        </p>
      ) : (
        <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
          {rows.map(({ repo, latestRun }) => (
            <li key={repo.id}>
              <Link
                to="/repos/$repoId/runs/$runId"
                params={{ repoId: repo.id, runId: latestRun!.id }}
                className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-sm transition-colors hover:bg-[var(--muted)]/40"
              >
                <div className="min-w-0">
                  <p className="truncate font-medium">{repo.name}</p>
                  <p
                    className="mt-0.5 text-xs"
                    style={{ color: 'var(--muted-foreground)' }}
                  >
                    {formatRelativeTime(latestRun!.finishedAt)} ·{' '}
                    {latestRun!.counts.total} findings
                  </p>
                </div>
                <DeltaBadges delta={latestRun!.delta} />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
