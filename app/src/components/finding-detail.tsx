import type { ReactNode } from 'react'

import { SeverityBadge } from '@/components/severity-badge'
import { StatusBadge } from '@/components/status-badge'
import type { Finding } from '@/lib/api'
import { formatLocation } from '@/lib/utils'

/**
 * Full context for one finding: explanation, code snippet, package metadata,
 * and reference links. The table view stays compact; this panel carries depth.
 */
export function FindingDetail({ finding }: { finding: Finding }) {
  const scanners = finding.scanners ?? (finding.scanner ? [finding.scanner] : [])
  const lineLabel =
    finding.locationStartLine && finding.locationStartLine > 0
      ? finding.locationEndLine &&
        finding.locationEndLine !== finding.locationStartLine
        ? `lines ${finding.locationStartLine}–${finding.locationEndLine}`
        : `line ${finding.locationStartLine}`
      : null

  return (
    <div
      className="space-y-4 rounded-md border p-4 text-sm"
      style={{ borderColor: 'var(--border)', backgroundColor: 'var(--muted)' }}
    >
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        {finding.category ? (
          <span
            className="rounded-md px-2 py-0.5 text-xs ring-1 ring-inset"
            style={{ color: 'var(--muted-foreground)', borderColor: 'var(--border)' }}
          >
            {finding.category}
          </span>
        ) : null}
        <StatusBadge status={finding.status} />
        {scanners.length > 1 ? (
          <span className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
            {scanners.length} scanners agree
          </span>
        ) : null}
      </div>

      {finding.message ? (
        <p className="leading-relaxed whitespace-pre-wrap">{finding.message}</p>
      ) : null}

      {finding.locationSnippet ? (
        <div className="space-y-1.5">
          <h3
            className="text-xs font-medium tracking-wide uppercase"
            style={{ color: 'var(--muted-foreground)' }}
          >
            {finding.category === 'secret' ? 'Identity hint' : 'Code'}
          </h3>
          <pre
            className="overflow-x-auto rounded-md border px-3 py-2 font-mono text-xs leading-relaxed"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
          >
            {lineLabel ? (
              <span
                className="mr-3 select-none"
                style={{ color: 'var(--muted-foreground)' }}
              >
                {lineLabel}
              </span>
            ) : null}
            {finding.locationSnippet}
          </pre>
          {finding.category === 'secret' ? (
            <p className="text-xs" style={{ color: 'var(--muted-foreground)' }}>
              Secret values are never stored — only a redacted hint or hash from the
              scanner.
            </p>
          ) : null}
        </div>
      ) : null}

      <dl className="grid gap-3 sm:grid-cols-2">
        <DetailItem label="Location">
          <code className="font-mono text-xs break-all">
            {formatLocation(finding.locationPath, finding.locationStartLine) ?? '—'}
          </code>
        </DetailItem>

        {finding.ruleId ? (
          <DetailItem label="Rule">
            <code className="font-mono text-xs">{finding.ruleId}</code>
          </DetailItem>
        ) : null}

        {scanners.length > 0 ? (
          <DetailItem label="Reported by">
            <span className="text-xs">{scanners.join(', ')}</span>
          </DetailItem>
        ) : null}

        {finding.packageName ? (
          <DetailItem label="Package">
            <span className="text-xs">
              <code className="font-mono">{finding.packageName}</code>
              {finding.packageVersion ? <> @ {finding.packageVersion}</> : null}
              {finding.packageEcosystem ? (
                <span style={{ color: 'var(--muted-foreground)' }}>
                  {' '}
                  ({finding.packageEcosystem})
                </span>
              ) : null}
            </span>
          </DetailItem>
        ) : null}

        {finding.fixedIn ? (
          <DetailItem label="Fixed in">
            <span className="text-xs text-emerald-700 dark:text-emerald-400">
              {finding.fixedIn}
            </span>
          </DetailItem>
        ) : null}

        {finding.aliases && finding.aliases.length > 0 ? (
          <DetailItem label="Also known as">
            <span className="font-mono text-xs">{finding.aliases.join(', ')}</span>
          </DetailItem>
        ) : null}
      </dl>

      {finding.refs && finding.refs.length > 0 ? (
        <div className="space-y-2">
          <h3
            className="text-xs font-medium tracking-wide uppercase"
            style={{ color: 'var(--muted-foreground)' }}
          >
            References
          </h3>
          <ul className="space-y-1 text-xs">
            {finding.refs.map((href) => (
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
      ) : null}
    </div>
  )
}

function DetailItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt
        className="text-xs font-medium tracking-wide uppercase"
        style={{ color: 'var(--muted-foreground)' }}
      >
        {label}
      </dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  )
}
