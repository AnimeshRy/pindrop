/** Static preview based on real CLI output from the project README. */
export function HomeScanPreview() {
  return (
    <section className="mx-auto max-w-6xl px-4 pb-16 sm:px-6">
      <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] lg:items-center">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">
            Four scanners. One readable result.
          </h2>
          <p className="mt-3 leading-relaxed text-[var(--muted-foreground)]">
            Trivy, OSV-Scanner, Opengrep, and TruffleHog run together. Pindrop
            normalizes the output, deduplicates overlap, and surfaces the issues worth
            your time first.
          </p>
        </div>

        <div
          className="overflow-hidden rounded-xl border font-mono text-xs sm:text-[13px]"
          style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
          aria-label="Example scan output"
        >
          <div
            className="border-b px-4 py-2 text-[11px] tracking-wide uppercase"
            style={{ borderColor: 'var(--border)', color: 'var(--muted-foreground)' }}
          >
            Terminal
          </div>
          <pre className="overflow-x-auto p-4 leading-6 text-[var(--foreground)]">
            <code>{`$ pindrop scan .

  ✔ trivy          8 findings   640ms
  ✔ osv            6 findings   1.2s
  ✔ opengrep      11 findings   2.1s
  ✔ trufflehog     0 findings   770ms

  4/4 scanners · 25 raw findings

SEVERITY  CATEGORY          RULE                 LOCATION
HIGH      misconfiguration  DS-0002              Dockerfile
HIGH      vulnerability     CVE-2024-21538       package-lock.json
HIGH      code              go-sql-query-from…   src/admin.go:22

19 findings  14 high  4 medium  1 low`}</code>
          </pre>
        </div>
      </div>
    </section>
  )
}
