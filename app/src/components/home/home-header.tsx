import { PindropLogo } from '@/components/pindrop-logo'
import { ThemeToggle } from '@/components/theme-toggle'
import { ButtonLink } from '@/components/ui/button'

interface HomeHeaderProps {
  signedIn: boolean
}

/** Sticky marketing header with anchor links and auth-aware CTA. */
export function HomeHeader({ signedIn }: HomeHeaderProps) {
  return (
    <header
      className="sticky top-0 z-20 border-b backdrop-blur-sm"
      style={{
        borderColor: 'var(--border)',
        backgroundColor: 'color-mix(in oklch, var(--background) 88%, transparent)',
      }}
    >
      <div className="mx-auto flex max-w-6xl items-center gap-4 px-4 py-3 sm:px-6">
        <PindropLogo />

        <nav aria-label="Primary" className="hidden items-center gap-6 md:flex">
          <a
            href="#features"
            className="text-sm text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
          >
            Features
          </a>
          <a
            href="#how-it-works"
            className="text-sm text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
          >
            How it works
          </a>
        </nav>

        <div className="ml-auto flex items-center gap-2 sm:gap-3">
          <ThemeToggle />
          {signedIn ? (
            <ButtonLink to="/dashboard">Open dashboard</ButtonLink>
          ) : (
            <ButtonLink to="/login">Sign in</ButtonLink>
          )}
        </div>
      </div>
    </header>
  )
}
