import { ButtonLink } from '@/components/ui/button'

interface HomeCtaProps {
  signedIn: boolean
}

/** Final conversion section before the footer. */
export function HomeCta({ signedIn }: HomeCtaProps) {
  return (
    <section className="pb-16 sm:pb-20">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div
          className="rounded-2xl border px-6 py-10 sm:px-10 sm:py-12"
          style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
        >
          <h2 className="max-w-xl text-2xl font-semibold tracking-tight text-balance">
            {signedIn
              ? 'Your account is ready. Open the dashboard to continue.'
              : 'Start with the CLI locally. Sign in when you want the hosted view.'}
          </h2>
          <p className="mt-3 max-w-xl leading-relaxed text-[var(--muted-foreground)]">
            The dashboard is where scan history, repository connections, and triage will
            live as the product expands.
          </p>
          <div className="mt-6">
            {signedIn ? (
              <ButtonLink to="/dashboard">Open dashboard</ButtonLink>
            ) : (
              <ButtonLink to="/login">Sign in</ButtonLink>
            )}
          </div>
        </div>
      </div>
    </section>
  )
}
