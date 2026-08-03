import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'

import { FindingsTable } from '@/components/FindingsTable'
import { SummaryTiles } from '@/components/SummaryTiles'
import { ApiError, fetchFindings, fetchSummary } from '@/lib/api'

export const Route = createFileRoute('/')({
  component: FindingsPage,
})

function FindingsPage() {
  const findings = useQuery({ queryKey: ['findings'], queryFn: fetchFindings })
  const summary = useQuery({ queryKey: ['summary'], queryFn: fetchSummary })

  if (findings.isPending || summary.isPending) {
    return <Skeleton />
  }

  const error = findings.error ?? summary.error
  if (error) {
    return <ErrorState error={error} />
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Findings</h1>
        {summary.data && (
          <p className="mt-1 text-sm" style={{ color: 'var(--muted-foreground)' }}>
            {summary.data.total} findings from{' '}
            {summary.data.scans.map((s) => s.scanner).join(', ') || 'no scanners'}
          </p>
        )}
      </div>

      {summary.data && <SummaryTiles summary={summary.data} />}
      {findings.data && <FindingsTable findings={findings.data} />}
    </div>
  )
}

function Skeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-6 w-40 rounded" style={{ background: 'var(--muted)' }} />
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {Array.from({ length: 6 }, (_, i) => (
          <div
            key={i}
            className="h-20 rounded-lg"
            style={{ background: 'var(--muted)' }}
          />
        ))}
      </div>
      <div className="h-64 rounded-lg" style={{ background: 'var(--muted)' }} />
    </div>
  )
}

/**
 * The overwhelmingly common failure is "you haven't scanned yet", which is a
 * setup step rather than a fault. The server sends the exact command to run, so
 * surface it rather than a generic error.
 */
function ErrorState({ error }: { error: Error }) {
  const isMissingReport = error instanceof ApiError && error.status === 503

  return (
    <div
      className="rounded-lg border p-6"
      style={{ borderColor: 'var(--border)', background: 'var(--card)' }}
    >
      <h2 className="font-medium">
        {isMissingReport ? 'No scan report yet' : 'Could not load findings'}
      </h2>
      <p className="mt-2 text-sm" style={{ color: 'var(--muted-foreground)' }}>
        {error.message}
      </p>
      {isMissingReport && (
        <pre
          className="mt-4 overflow-x-auto rounded-md p-3 text-xs"
          style={{ background: 'var(--muted)' }}
        >
          pindrop scan . --format json --out .pindrop/report.json
        </pre>
      )}
    </div>
  )
}
