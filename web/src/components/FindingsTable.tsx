import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from '@tanstack/react-table'
import { useMemo, useState } from 'react'

import { SeverityBadge } from '@/components/SeverityBadge'
import { StatusBadge } from '@/components/StatusBadge'
import { SEVERITY_RANK, type Finding, type Status } from '@/lib/api'
import { formatLocation } from '@/lib/utils'

/**
 * A finding, optionally carrying the lifecycle status it held in the run being
 * viewed. Status is a property of a run, not of a finding — a report served
 * without history has none — so it is optional here rather than on `Finding`.
 */
export type FindingRow = Finding & { status?: Status }

const columnHelper = createColumnHelper<FindingRow>()

export function FindingsTable({ findings }: { findings: FindingRow[] }) {
  // Severity descending is the only sensible default: the product exists to put
  // the worst thing first.
  const [sorting, setSorting] = useState<SortingState>([{ id: 'severity', desc: true }])
  const [filter, setFilter] = useState('')

  // The column is shown only when statuses are actually present, so a
  // single-report view does not grow a permanently empty column.
  const hasStatus = findings.some((f) => f.status !== undefined)

  const columns = useMemo(
    () => [
      ...(hasStatus
        ? [
            columnHelper.accessor((row) => row.status ?? '', {
              id: 'status',
              header: 'Status',
              cell: (info) => {
                const status = info.row.original.status
                return status ? <StatusBadge status={status} /> : null
              },
            }),
          ]
        : []),
      columnHelper.accessor('severity', {
        header: 'Severity',
        cell: (info) => <SeverityBadge severity={info.getValue()} />,
        // Sort by rank, not alphabetically — otherwise "critical" sorts below
        // "low" and the table actively misleads.
        sortingFn: (a, b) =>
          SEVERITY_RANK[a.original.severity] - SEVERITY_RANK[b.original.severity],
      }),
      columnHelper.accessor('category', {
        header: 'Category',
        cell: (info) => (
          <span className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
            {info.getValue()}
          </span>
        ),
      }),
      columnHelper.accessor('ruleId', {
        header: 'Rule',
        cell: (info) => <code className="font-mono text-xs">{info.getValue()}</code>,
      }),
      columnHelper.accessor(
        (row) => formatLocation(row.location.path, row.location.startLine),
        {
          id: 'location',
          header: 'Location',
          cell: (info) => (
            <code
              className="font-mono text-xs"
              style={{ color: 'var(--muted-foreground)' }}
            >
              {info.getValue()}
            </code>
          ),
        },
      ),
      columnHelper.accessor('title', {
        header: 'Summary',
        cell: (info) => {
          const finding = info.row.original
          return (
            <div className="max-w-xl">
              <div className="truncate text-sm">{info.getValue()}</div>
              {finding.fixedIn && (
                <div className="mt-0.5 text-xs text-emerald-600 dark:text-emerald-400">
                  Fixed in {finding.fixedIn}
                </div>
              )}
            </div>
          )
        },
      }),
    ],
    [hasStatus],
  )

  const table = useReactTable({
    data: findings,
    columns,
    state: { sorting, globalFilter: filter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  })

  const rows = table.getRowModel().rows

  return (
    <div className="space-y-3">
      <input
        type="search"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter findings…"
        aria-label="Filter findings"
        className="w-full max-w-sm rounded-md border px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-blue-500/40"
        style={{ borderColor: 'var(--border)', background: 'var(--card)' }}
      />

      {/* Wide tables scroll inside their own container so the page body never
          scrolls horizontally. */}
      <div
        className="overflow-x-auto rounded-lg border"
        style={{ borderColor: 'var(--border)' }}
      >
        <table className="w-full border-collapse text-left text-sm">
          <thead style={{ background: 'var(--muted)' }}>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    onClick={header.column.getToggleSortingHandler()}
                    className="cursor-pointer px-4 py-2.5 text-xs font-medium tracking-wide uppercase select-none"
                    style={{ color: 'var(--muted-foreground)' }}
                  >
                    {flexRender(header.column.columnDef.header, header.getContext())}
                    {{ asc: ' ↑', desc: ' ↓' }[header.column.getIsSorted() as string] ??
                      ''}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-10 text-center text-sm"
                  style={{ color: 'var(--muted-foreground)' }}
                >
                  No findings match this filter.
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr
                  key={row.id}
                  className="border-t hover:bg-black/[0.02] dark:hover:bg-white/[0.03]"
                  style={{ borderColor: 'var(--border)' }}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-4 py-2.5 align-top">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <p className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
        Showing {rows.length} of {findings.length} findings
      </p>
    </div>
  )
}
