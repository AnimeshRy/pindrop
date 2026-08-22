import { useMemo } from 'react'

import { SEVERITIES, type Severity } from '@/lib/api'
import type { SeverityCounts } from '@/lib/dashboard'

const SLICE_STYLES: Record<Severity, { label: string; stroke: string }> = {
  critical: { label: 'Critical', stroke: '#dc2626' },
  high: { label: 'High', stroke: '#ea580c' },
  medium: { label: 'Medium', stroke: '#f59e0b' },
  low: { label: 'Low', stroke: '#eab308' },
  info: { label: 'Info', stroke: '#2563eb' },
  unknown: { label: 'Unknown', stroke: '#71717a' },
}

const SLICES = SEVERITIES.map((severity) => ({
  severity,
  ...SLICE_STYLES[severity],
}))

const RADIUS = 42
const STROKE = 14
const CENTER = 52
const CIRC = 2 * Math.PI * RADIUS

/**
 * Open findings by severity as a donut chart plus legend.
 * SVG only — no chart library dependency.
 */
export function SeverityBreakdown({ counts }: { counts: SeverityCounts }) {
  const total = SEVERITIES.reduce((sum, severity) => sum + counts[severity], 0)

  const arcs = useMemo(() => {
    return SLICES.reduce<{
      arcs: Array<{
        severity: string
        stroke: string
        dashArray: string
        dashOffset: number
      }>
      offset: number
    }>(
      (acc, slice) => {
        const count = counts[slice.severity]
        if (count <= 0 || total === 0) {
          return acc
        }
        const length = (count / total) * CIRC
        return {
          offset: acc.offset + length,
          arcs: [
            ...acc.arcs,
            {
              severity: slice.severity,
              stroke: slice.stroke,
              dashArray: `${length} ${CIRC - length}`,
              dashOffset: -acc.offset,
            },
          ],
        }
      },
      { arcs: [], offset: 0 },
    ).arcs
  }, [counts, total])

  return (
    <div
      className="rounded-xl border p-4"
      style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
    >
      <h2 className="text-sm font-medium">Open findings by severity</h2>

      {total === 0 ? (
        <p className="mt-4 text-sm" style={{ color: 'var(--muted-foreground)' }}>
          No open findings to chart yet.
        </p>
      ) : (
        <div className="mt-4 flex flex-col items-center gap-6 sm:flex-row sm:items-start">
          <div className="relative shrink-0">
            <svg
              width={CENTER * 2}
              height={CENTER * 2}
              viewBox={`0 0 ${CENTER * 2} ${CENTER * 2}`}
              role="img"
              aria-label="Open findings by severity donut chart"
            >
              <circle
                cx={CENTER}
                cy={CENTER}
                r={RADIUS}
                fill="none"
                stroke="var(--muted)"
                strokeWidth={STROKE}
              />
              {arcs.map((arc) => (
                  <circle
                    key={arc.severity}
                    cx={CENTER}
                    cy={CENTER}
                    r={RADIUS}
                    fill="none"
                    stroke={arc.stroke}
                    strokeWidth={STROKE}
                    strokeDasharray={arc.dashArray}
                    strokeDashoffset={arc.dashOffset}
                    transform={`rotate(-90 ${CENTER} ${CENTER})`}
                  />
                ))}
            </svg>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-semibold tabular-nums">{total}</span>
              <span className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
                open
              </span>
            </div>
          </div>

          <ul className="w-full flex-1 space-y-2">
            {SLICES.filter((slice) => counts[slice.severity] > 0).map((slice) => {
              const count = counts[slice.severity]
              const pct = total > 0 ? Math.round((count / total) * 100) : 0
              return (
                <li key={slice.severity} className="flex items-center gap-3 text-sm">
                  <span
                    aria-hidden
                    className="size-2.5 shrink-0 rounded-full"
                    style={{ backgroundColor: slice.stroke }}
                  />
                  <span className="w-16 text-xs" style={{ color: 'var(--muted-foreground)' }}>
                    {slice.label}
                  </span>
                  <div
                    className="h-1.5 flex-1 overflow-hidden rounded-full"
                    style={{ backgroundColor: 'var(--muted)' }}
                  >
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${pct}%`,
                        backgroundColor: slice.stroke,
                      }}
                    />
                  </div>
                  <span
                    className="w-10 text-right text-xs tabular-nums"
                    style={{ color: 'var(--muted-foreground)' }}
                  >
                    {count}
                  </span>
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </div>
  )
}
