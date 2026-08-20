const steps = [
  {
    step: '01',
    title: 'Setup',
    description:
      'Run `pindrop setup` once. Pinned scanner binaries land in ~/.pindrop/bin with digest verification.',
  },
  {
    step: '02',
    title: 'Scan',
    description:
      'Point Pindrop at any directory. Four scanners run in parallel and merge into one ranked report.',
  },
  {
    step: '03',
    title: 'Review',
    description:
      'Browse history locally with `pindrop serve`, or sign in here as cloud features roll out.',
  },
] as const

/** Three-step workflow: setup, scan, review. */
export function HomeWorkflow() {
  return (
    <section id="how-it-works" className="py-16 sm:py-20">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="max-w-2xl">
          <h2 className="text-2xl font-semibold tracking-tight">How it works</h2>
          <p className="mt-3 leading-relaxed text-[var(--muted-foreground)]">
            Local-first today. Sign in when you want hosted results and repository
            workflows.
          </p>
        </div>

        <ol className="mt-10 grid gap-6 md:grid-cols-3">
          {steps.map(({ step, title, description }) => (
            <li
              key={step}
              className="relative rounded-xl border p-6"
              style={{ borderColor: 'var(--border)' }}
            >
              <span className="text-sm font-medium text-[var(--accent)]">{step}</span>
              <h3 className="mt-3 font-medium">{title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-[var(--muted-foreground)]">
                {description}
              </p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  )
}
