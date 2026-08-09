import type { ReactNode } from 'react'

import { SeverityBadge } from '@/components/SeverityBadge'
import { StatusBadge } from '@/components/StatusBadge'
import type { Finding, Status } from '@/lib/api'
import { formatLocation } from '@/lib/utils'

type FindingDetailRow = Finding & { status?: Status }

/**
 * Full context for one finding: explanation, offending code, dependency
 * metadata, and links. Scanners already supply this in the report JSON; the
 * table view only shows a one-line summary.
 */
export function FindingDetail({ finding }: { finding: FindingDetailRow }) {
  const scanners = finding.scanners ?? [finding.scanner]
  const lineLabel =
    finding.location.startLine && finding.location.startLine > 0
      ? finding.location.endLine && finding.location.endLine !== finding.location.startLine
        ? `lines ${finding.location.startLine}–${finding.location.endLine}`
        : `line ${finding.location.startLine}`
      : null

  return (
    <div
      className="space-y-4 rounded-md border p-4 text-sm"
      style={{ borderColor: 'var(--border)', background: 'var(--muted)' }}
    >
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        <span
          className="rounded-md px-2 py-0.5 text-xs ring-1 ring-inset"
          style={{ color: 'var(--muted-foreground)', borderColor: 'var(--border)' }}
        >
          {finding.category}
        </span>
        {finding.status && <StatusBadge status={finding.status} />}
        {scanners.length > 1 && (
          <span className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
            {scanners.length} scanners agree
          </span>
        )}
      </div>

      {finding.message && (
        <p className="leading-relaxed whitespace-pre-wrap" style={{ color: 'var(--foreground)' }}>
          {finding.message}
        </p>
      )}

      {finding.location.snippet && (
        <div className="space-y-1.5">
          <h3
            className="text-xs font-medium tracking-wide uppercase"
            style={{ color: 'var(--muted-foreground)' }}
          >
            {finding.category === 'secret' ? 'Identity hint' : 'Code'}
          </h3>
          <pre
            className="overflow-x-auto rounded-md border px-3 py-2 font-mono text-xs leading-relaxed"
            style={{ borderColor: 'var(--border)', background: 'var(--card)' }}
          >
            {lineLabel && (
              <span className="mr-3 select-none" style={{ color: 'var(--muted-foreground)' }}>
                {lineLabel}
              </span>
            )}
            {finding.location.snippet}
          </pre>
          {finding.category === 'secret' && (
            <p className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
              Secret values are never stored — only a redacted hint or hash from the scanner.
            </p>
          )}
        </div>
      )}

      <dl className="grid gap-3 sm:grid-cols-2">
        <DetailItem label="Location">
          <code className="font-mono text-xs break-all">
            {formatLocation(finding.location.path, finding.location.startLine)}
          </code>
        </DetailItem>

        <DetailItem label="Rule">
          <code className="font-mono text-xs">{finding.ruleId}</code>
        </DetailItem>

        <DetailItem label="Reported by">
          <span className="text-xs">{scanners.join(', ')}</span>
        </DetailItem>

        {finding.package && (
          <DetailItem label="Package">
            <span className="text-xs">
              <code className="font-mono">{finding.package.name}</code>
              {finding.package.version && <> @ {finding.package.version}</>}
              {finding.package.ecosystem && (
                <span style={{ color: 'var(--muted-foreground)' }}>
                  {' '}
                  ({finding.package.ecosystem})
                </span>
              )}
            </span>
          </DetailItem>
        )}

        {finding.fixedIn && (
          <DetailItem label="Fixed in">
            <span className="text-xs text-emerald-700 dark:text-emerald-400">
              {finding.fixedIn}
            </span>
          </DetailItem>
        )}

        {finding.aliases && finding.aliases.length > 0 && (
          <DetailItem label="Also known as">
            <span className="font-mono text-xs">{finding.aliases.join(', ')}</span>
          </DetailItem>
        )}
      </dl>

      {finding.references && finding.references.length > 0 && (
        <div className="space-y-2">
          <h3
            className="text-xs font-medium tracking-wide uppercase"
            style={{ color: 'var(--muted-foreground)' }}
          >
            References
          </h3>
          <ul className="space-y-1 text-xs">
            {finding.references.map((href) => (
              <li key={href}>
                <a
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="break-all underline hover:no-underline"
                >
                  {href}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function DetailItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium tracking-wide uppercase" style={{ color: 'var(--muted-foreground)' }}>
        {label}
      </dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  )
}
