import { Link, useNavigate } from '@tanstack/react-router'
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from '@tanstack/react-table'
import { useMemo, useState } from 'react'

import { DeltaBadges } from '@/components/DeltaBadges'
import { SEVERITIES, type DeltaCounts, type Repo, type Severity } from '@/lib/api'
import { cn, formatAbsolute, formatRelative } from '@/lib/utils'

const columnHelper = createColumnHelper<Repo>()

/** Severities worth showing inline. Info and unknown are noise in a list view. */
const HEADLINE_SEVERITIES: readonly Severity[] = SEVERITIES.filter(
  (s) => s !== 'info' && s !== 'unknown',
)

const severityTone: Record<Severity, string> = {
  critical: 'text-red-700 dark:text-red-400',
  high: 'text-orange-700 dark:text-orange-400',
  medium: 'text-amber-700 dark:text-amber-400',
  low: 'text-yellow-700 dark:text-yellow-500',
  info: 'text-blue-700 dark:text-blue-400',
  unknown: 'text-zinc-600 dark:text-zinc-400',
}

/**
 * Open findings by severity, abbreviated.
 *
 * Each count is labelled with its severity's initial and given a full text
 * label for assistive technology, so the row is readable without relying on the
 * colour to say which number is which.
 */
function OpenCounts({ repo }: { repo: Repo }) {
  const shown = HEADLINE_SEVERITIES.filter((s) => (repo.open.bySeverity?.[s] ?? 0) > 0)

  if (shown.length === 0) {
    return (
      <span className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
        none open
      </span>
    )
  }

  return (
    <span className="flex flex-wrap items-center gap-2">
      {shown.map((severity) => (
        <span
          key={severity}
          className={cn('text-xs font-medium tabular-nums', severityTone[severity])}
        >
          <span aria-hidden>
            {repo.open.bySeverity?.[severity]} {severity.charAt(0).toUpperCase()}
          </span>
          <span className="sr-only">
            {repo.open.bySeverity?.[severity]} {severity}
          </span>
        </span>
      ))}
    </span>
  )
}

/**
 * The repository list: what has been scanned, how stale it is, and what is
 * open.
 *
 * `deltas` is passed in rather than read from the repo, because the API's
 * repository summary carries current open counts but not what the last run
 * changed — that lives on the run. The caller fetches it per repository and
 * this renders whatever has arrived, so the table is useful before they all do.
 */
export function RepoTable({
  repos,
  deltas = {},
}: {
  repos: Repo[]
  deltas?: Record<string, DeltaCounts | undefined>
}) {
  const navigate = useNavigate()
  const [sorting, setSorting] = useState<SortingState>([{ id: 'lastRunAt', desc: true }])

  const columns = useMemo(
    () => [
      columnHelper.accessor('name', {
        header: 'Repository',
        cell: (info) => (
          <div className="flex items-center gap-2">
            {/* A real link, so the row is reachable by keyboard and openable
                in a new tab, even though the whole row is also clickable. */}
            <Link
              to="/repos/$repoId"
              params={{ repoId: info.row.original.id }}
              className="font-medium hover:underline"
            >
              {info.getValue()}
            </Link>
            {info.row.original.missing && (
              <span
                className="rounded px-1.5 py-0.5 text-xs ring-1 ring-inset ring-amber-600/30"
                title="This checkout is no longer on disk. Its history is still readable."
              >
                checkout missing
              </span>
            )}
          </div>
        ),
      }),
      columnHelper.accessor('path', {
        header: 'Path',
        cell: (info) => (
          <code
            className="block max-w-[22rem] truncate font-mono text-xs"
            style={{ color: 'var(--muted-foreground)' }}
            title={info.getValue()}
          >
            {info.getValue()}
          </code>
        ),
      }),
      columnHelper.accessor('lastRunAt', {
        header: 'Last scanned',
        cell: (info) => (
          <span
            className="text-xs whitespace-nowrap"
            style={{ color: 'var(--muted-foreground)' }}
            title={formatAbsolute(info.getValue())}
          >
            {formatRelative(info.getValue())}
          </span>
        ),
        sortingFn: (a, b) =>
          new Date(a.original.lastRunAt).getTime() -
          new Date(b.original.lastRunAt).getTime(),
      }),
      columnHelper.accessor((row) => row.open.total, {
        id: 'open',
        header: 'Open',
        cell: (info) => (
          <div className="space-y-1">
            <div className="text-sm font-medium tabular-nums">{info.getValue()}</div>
            <OpenCounts repo={info.row.original} />
          </div>
        ),
      }),
      columnHelper.display({
        id: 'delta',
        header: 'Last run',
        cell: (info) => {
          const delta = deltas[info.row.original.id]
          if (!delta) {
            return (
              <span className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
                —
              </span>
            )
          }
          return <DeltaBadges delta={delta} />
        },
      }),
    ],
    [deltas],
  )

  const table = useReactTable({
    data: repos,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  return (
    // Wide tables scroll inside their own container so the page body never
    // scrolls horizontally.
    <div className="overflow-x-auto rounded-lg border" style={{ borderColor: 'var(--border)' }}>
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
                  {{ asc: ' ↑', desc: ' ↓' }[header.column.getIsSorted() as string] ?? ''}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => (
            <tr
              key={row.id}
              onClick={() =>
                void navigate({
                  to: '/repos/$repoId',
                  params: { repoId: row.original.id },
                })
              }
              className="cursor-pointer border-t hover:bg-black/[0.02] dark:hover:bg-white/[0.03]"
              style={{ borderColor: 'var(--border)' }}
            >
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id} className="px-4 py-3 align-top">
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
