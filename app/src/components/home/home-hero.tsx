import { ArrowRight, Github } from 'lucide-react'

import { ButtonLink } from '@/components/ui/button'

interface HomeHeroProps {
  signedIn: boolean
}

/** Outcome-led hero with auth-aware primary action. */
export function HomeHero({ signedIn }: HomeHeroProps) {
  return (
    <section className="mx-auto max-w-6xl px-4 pt-14 pb-16 sm:px-6 sm:pt-20 sm:pb-20">
      <div className="max-w-3xl">
        <p className="text-sm font-medium tracking-wide text-[var(--accent)] uppercase">
          Security scanning for builders
        </p>
        <h1 className="mt-4 text-4xl font-semibold tracking-tight text-balance sm:text-5xl sm:leading-[1.1]">
          Know what to fix, not everything that&apos;s wrong.
        </h1>
        <p className="mt-5 max-w-2xl text-lg leading-relaxed text-pretty text-[var(--muted-foreground)]">
          Pindrop runs four scanners, deduplicates overlap, ranks what matters, and
          keeps a stable history so the next scan shows what changed.
        </p>

        <div className="mt-8 flex flex-wrap items-center gap-3">
          {signedIn ? (
            <ButtonLink to="/dashboard" className="gap-2 px-5">
              Open dashboard
              <ArrowRight className="size-4" aria-hidden />
            </ButtonLink>
          ) : (
            <ButtonLink to="/login" className="gap-2 px-5">
              Sign in to get started
              <ArrowRight className="size-4" aria-hidden />
            </ButtonLink>
          )}
          <a
            href="https://github.com/AnimeshRy/pindrop"
            target="_blank"
            rel="noreferrer"
            className="inline-flex h-10 items-center gap-2 rounded-lg border px-4 text-sm font-medium transition-colors hover:bg-[var(--muted)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:outline-none"
            style={{ borderColor: 'var(--border)' }}
          >
            <Github className="size-4" aria-hidden />
            View on GitHub
          </a>
        </div>

        <dl className="mt-12 grid gap-6 sm:grid-cols-3">
          <div>
            <dt className="text-2xl font-semibold tracking-tight">4</dt>
            <dd className="mt-1 text-sm text-[var(--muted-foreground)]">
              Scanners in one binary
            </dd>
          </div>
          <div>
            <dt className="text-2xl font-semibold tracking-tight">1</dt>
            <dd className="mt-1 text-sm text-[var(--muted-foreground)]">
              Ranked table to read
            </dd>
          </div>
          <div>
            <dt className="text-2xl font-semibold tracking-tight">0</dt>
            <dd className="mt-1 text-sm text-[var(--muted-foreground)]">
              Accounts required locally
            </dd>
          </div>
        </dl>
      </div>
    </section>
  )
}
