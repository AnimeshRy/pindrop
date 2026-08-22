import { Link } from '@tanstack/react-router'
import { useMemo, useState } from 'react'

import { SeverityBadge } from '@/components/severity-badge'
import { StatusBadge } from '@/components/status-badge'
import { SEVERITIES, STATUSES, normalizeSeverity, normalizeStatus } from '@/lib/api'
import type { RankedFinding } from '@/lib/dashboard'
import { formatLocation, formatRelativeTime } from '@/lib/utils'

/**
 * The org's worst open findings, worst severity first.
 * Small client-side filters sit above the table; age comes from firstSeenAt.
 */
export function RankedIssues({ findings }: { findings: RankedFinding[] }) {
  const [severityFilter, setSeverityFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  const filtered = useMemo(() => {
    return findings.filter((finding) => {
      if (
        severityFilter &&
        normalizeSeverity(finding.severity) !== severityFilter
      ) {
        return false
      }
      if (statusFilter) {
        const status = normalizeStatus(finding.status)
        if (status !== statusFilter) {
          return false
        }
      }
      return true
    })
  }, [findings, severityFilter, statusFilter])

  return (
    <div
      className="rounded-xl border"
      style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
    >
      <div className="border-b px-4 py-3" style={{ borderColor: 'var(--border)' }}>
        <h2 className="text-sm font-medium">Ranked issues</h2>
        <p className="mt-0.5 text-xs" style={{ color: 'var(--muted-foreground)' }}>
          Most severe open findings across all synced repositories
        </p>
      </div>

      {findings.length === 0 ? (
        <p className="p-4 text-sm" style={{ color: 'var(--muted-foreground)' }}>
          No open findings from the latest scan of each repository.
        </p>
      ) : (
        <>
          <div className="flex flex-wrap gap-3 border-b px-4 py-3" style={{ borderColor: 'var(--border)' }}>
            <FilterSelect
              label="Severity"
              value={severityFilter}
              onChange={setSeverityFilter}
              options={[
                { value: '', label: 'All severities' },
                ...SEVERITIES.map((s) => ({ value: s, label: s })),
              ]}
            />
            <FilterSelect
              label="Status"
              value={statusFilter}
              onChange={setStatusFilter}
              options={[
                { value: '', label: 'All statuses' },
                ...STATUSES.map((s) => ({ value: s, label: s })),
              ]}
            />
          </div>

          {filtered.length === 0 ? (
            <p className="p-4 text-sm" style={{ color: 'var(--muted-foreground)' }}>
              No findings match the selected filters.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-sm">
                <thead>
                  <tr style={{ color: 'var(--muted-foreground)' }}>
                    <Th>Severity</Th>
                    <Th>Issue</Th>
                    <Th>Category</Th>
                    <Th>Detected by</Th>
                    <Th>Status</Th>
                    <Th>Age</Th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((finding) => {
                    const scanners =
                      finding.scanners ?? (finding.scanner ? [finding.scanner] : [])
                    const location = formatLocation(
                      finding.locationPath,
                      finding.locationStartLine,
                    )

                    return (
                      <tr
                        key={`${finding.repoId}:${finding.fingerprint}`}
                        className="border-t"
                        style={{ borderColor: 'var(--border)' }}
                      >
                        <td className="px-4 py-2.5 align-top">
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td className="max-w-md px-4 py-2.5 align-top">
                          <p className="truncate text-sm">
                            {finding.title || finding.ruleId}
                          </p>
                          <p
                            className="mt-0.5 truncate font-mono text-xs"
                            style={{ color: 'var(--muted-foreground)' }}
                          >
                            <Link
                              to="/repos/$repoId"
                              params={{ repoId: finding.repoId }}
                              className="hover:underline"
                            >
                              {finding.repoName}
                            </Link>
                            {location ? ` · ${location}` : ''}
                          </p>
                        </td>
                        <td
                          className="px-4 py-2.5 align-top text-xs"
                          style={{ color: 'var(--muted-foreground)' }}
                        >
                          {finding.category ?? '—'}
                        </td>
                        <td
                          className="px-4 py-2.5 align-top text-xs"
                          style={{ color: 'var(--muted-foreground)' }}
                        >
                          {scanners.length > 0 ? scanners.join(', ') : '—'}
                        </td>
                        <td className="px-4 py-2.5 align-top">
                          <StatusBadge status={finding.status} />
                        </td>
                        <td
                          className="px-4 py-2.5 align-top text-xs whitespace-nowrap"
                          style={{ color: 'var(--muted-foreground)' }}
                        >
                          {finding.firstSeenAt
                            ? formatRelativeTime(finding.firstSeenAt)
                            : '—'}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  )
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  options: Array<{ value: string; label: string }>
}) {
  return (
    <label className="flex items-center gap-2 text-xs" style={{ color: 'var(--muted-foreground)' }}>
      {label}
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-md border px-2 py-1 text-sm text-[var(--foreground)]"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
      >
        {options.map((option) => (
          <option key={option.value || 'all'} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  )
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-4 py-2.5 text-xs font-medium tracking-wide uppercase">
      {children}
    </th>
  )
}
