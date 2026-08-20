import { Link } from '@tanstack/react-router'

import { PindropLogo } from '@/components/pindrop-logo'

/** Minimal marketing footer with product links. */
export function HomeFooter() {
  return (
    <footer className="border-t py-10" style={{ borderColor: 'var(--border)' }}>
      <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <PindropLogo to="/" />

        <nav
          aria-label="Footer"
          className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm"
        >
          <a
            href="https://github.com/AnimeshRy/pindrop"
            target="_blank"
            rel="noreferrer"
            className="text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
          >
            GitHub
          </a>
          <Link
            to="/login"
            className="text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
          >
            Sign in
          </Link>
          <Link
            to="/dashboard"
            className="text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
          >
            Dashboard
          </Link>
        </nav>

        <p className="text-sm text-[var(--muted-foreground)]">
          © {new Date().getFullYear()} Pindrop
        </p>
      </div>
    </footer>
  )
}
