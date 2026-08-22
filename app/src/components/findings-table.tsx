import { Fragment, useEffect, useState } from 'react'

import { FindingDetail } from '@/components/finding-detail'
import { Pagination } from '@/components/pagination'
import { SeverityBadge } from '@/components/severity-badge'
import { StatusBadge } from '@/components/status-badge'
import {
  SEVERITIES,
  STATUSES,
  type Finding,
  type FindingListParams,
} from '@/lib/api'
import { cn, formatLocation, formatRelativeTime } from '@/lib/utils'

/**
 * Paginated, filterable findings table for one scan run.
 * Filters are sent to the server; row click expands full finding detail.
 */
export function FindingsTable({
  findings,
  total,
  params,
  loading,
  onParamsChange,
}: {
  findings: Finding[]
  total: number
  params: FindingListParams
  loading: boolean
  onParamsChange: (patch: Partial<FindingListParams>) => void
}) {
  const [selected, setSelected] = useState<string | null>(null)
  const [searchInput, setSearchInput] = useState(params.q ?? '')

  // Debounce free-text search so we do not hit the API on every keystroke.
  useEffect(() => {
    const handle = window.setTimeout(() => {
      const trimmed = searchInput.trim()
      if (trimmed !== (params.q ?? '')) {
        onParamsChange({ q: trimmed || undefined, offset: 0 })
      }
    }, 300)
    return () => window.clearTimeout(handle)
  }, [searchInput, params.q, onParamsChange])

  const limit = params.limit ?? 50
  const offset = params.offset ?? 0

  function updateFilter(patch: Partial<FindingListParams>) {
    onParamsChange({ ...patch, offset: 0 })
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <FilterSelect
          label="Severity"
          value={params.severity ?? ''}
          onChange={(value) =>
            updateFilter({ severity: value || undefined })
          }
          options={[{ value: '', label: 'All severities' }, ...SEVERITIES.map((s) => ({ value: s, label: s }))]}
        />
        <FilterSelect
          label="Status"
          value={params.status ?? ''}
          onChange={(value) => updateFilter({ status: value || undefined })}
          options={[
            { value: '', label: 'All statuses' },
            ...STATUSES.map((s) => ({ value: s, label: s })),
          ]}
        />
        <div className="min-w-[12rem] flex-1">
          <label
            className="mb-1 block text-xs font-medium uppercase tracking-wide"
            style={{ color: 'var(--muted-foreground)' }}
          >
            Search
          </label>
          <input
            type="search"
            value={searchInput}
            onChange={(event) => setSearchInput(event.target.value)}
            placeholder="Filter findings…"
            className="w-full rounded-md border px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-blue-500/40"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
          />
        </div>
      </div>

      <div
        className="overflow-x-auto rounded-xl border"
        style={{ borderColor: 'var(--border)' }}
      >
        <table className="w-full border-collapse text-left text-sm">
          <thead style={{ backgroundColor: 'var(--muted)' }}>
            <tr style={{ color: 'var(--muted-foreground)' }}>
              <Th>Severity</Th>
              <Th>Status</Th>
              <Th>Issue</Th>
              <Th>Location</Th>
              <Th>Age</Th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td
                  colSpan={5}
                  className="px-4 py-10 text-center text-sm"
                  style={{ color: 'var(--muted-foreground)' }}
                >
                  Loading findings…
                </td>
              </tr>
            ) : findings.length === 0 ? (
              <tr>
                <td
                  colSpan={5}
                  className="px-4 py-10 text-center text-sm"
                  style={{ color: 'var(--muted-foreground)' }}
                >
                  No findings match this filter.
                </td>
              </tr>
            ) : (
              findings.map((finding) => {
                const isSelected = selected === finding.fingerprint
                const location = formatLocation(
                  finding.locationPath,
                  finding.locationStartLine,
                )

                return (
                  <Fragment key={finding.fingerprint}>
                    <tr
                      role="button"
                      tabIndex={0}
                      aria-expanded={isSelected}
                      onClick={() =>
                        setSelected(isSelected ? null : finding.fingerprint)
                      }
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          setSelected(isSelected ? null : finding.fingerprint)
                        }
                      }}
                      className={cn(
                        'cursor-pointer border-t hover:bg-black/[0.02] dark:hover:bg-white/[0.03]',
                        isSelected && 'bg-black/[0.03] dark:bg-white/[0.04]',
                      )}
                      style={{ borderColor: 'var(--border)' }}
                    >
                      <td className="px-4 py-2.5 align-top">
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="px-4 py-2.5 align-top">
                        <StatusBadge status={finding.status} />
                      </td>
                      <td className="max-w-md px-4 py-2.5 align-top">
                        <p className="truncate font-medium">
                          {finding.title || finding.ruleId || 'Untitled finding'}
                        </p>
                        {finding.category ? (
                          <p
                            className="mt-0.5 truncate text-xs"
                            style={{ color: 'var(--muted-foreground)' }}
                          >
                            {finding.category}
                          </p>
                        ) : null}
                      </td>
                      <td
                        className="px-4 py-2.5 align-top font-mono text-xs"
                        style={{ color: 'var(--muted-foreground)' }}
                      >
                        {location ?? '—'}
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
                    {isSelected ? (
                      <tr style={{ borderColor: 'var(--border)' }}>
                        <td colSpan={5} className="border-t px-4 py-3">
                          <FindingDetail finding={finding} />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      <Pagination
        total={total}
        limit={limit}
        offset={offset}
        onOffsetChange={(nextOffset) => onParamsChange({ offset: nextOffset })}
        onLimitChange={(nextLimit) =>
          onParamsChange({ limit: nextLimit, offset: 0 })
        }
      />

      <p className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
        Click a row for the full explanation, code snippet, and references.
      </p>
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
    <div>
      <label
        className="mb-1 block text-xs font-medium uppercase tracking-wide"
        style={{ color: 'var(--muted-foreground)' }}
      >
        {label}
      </label>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-md border px-2.5 py-1.5 text-sm"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
      >
        {options.map((option) => (
          <option key={option.value || 'all'} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  )
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-4 py-2.5 text-xs font-medium tracking-wide uppercase">
      {children}
    </th>
  )
}
