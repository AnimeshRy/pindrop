import { GitCompare, Layers, ShieldCheck } from 'lucide-react'

const features = [
  {
    icon: Layers,
    title: 'Unified scanning',
    description:
      'One command runs Trivy, OSV-Scanner, Opengrep, and TruffleHog. One table replaces four JSON shapes.',
  },
  {
    icon: ShieldCheck,
    title: 'Useful prioritization',
    description:
      'Cross-tool dedup and ranking cut noise down to findings you can actually triage in one sitting.',
  },
  {
    icon: GitCompare,
    title: 'Stable history',
    description:
      'Every run is recorded. The next scan shows what is new, recurring, or no longer detected.',
  },
] as const

/** Three concise product benefits backed by existing CLI capabilities. */
export function HomeFeatures() {
  return (
    <section
      id="features"
      className="border-y py-16 sm:py-20"
      style={{ borderColor: 'var(--border)' }}
    >
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="max-w-2xl">
          <h2 className="text-2xl font-semibold tracking-tight">
            Built for teams who want signal, not noise.
          </h2>
          <p className="mt-3 leading-relaxed text-[var(--muted-foreground)]">
            Free scanners are easy to install. Pindrop is the correlation layer that
            makes them usable.
          </p>
        </div>

        <ul className="mt-10 grid gap-6 sm:grid-cols-3">
          {features.map(({ icon: Icon, title, description }) => (
            <li
              key={title}
              className="rounded-xl border p-6"
              style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
            >
              <div
                className="inline-flex size-9 items-center justify-center rounded-lg"
                style={{
                  backgroundColor: 'var(--accent-muted)',
                  color: 'var(--accent)',
                }}
              >
                <Icon className="size-4" aria-hidden />
              </div>
              <h3 className="mt-4 font-medium">{title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-[var(--muted-foreground)]">
                {description}
              </p>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}
