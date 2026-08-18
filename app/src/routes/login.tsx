import { createFileRoute, redirect } from '@tanstack/react-router'
import { Github } from 'lucide-react'
import { useState } from 'react'

import { cn } from '@/lib/utils'

export const Route = createFileRoute('/login')({
  beforeLoad: ({ context }) => {
    if (context.auth.loading) {
      return
    }
    if (context.auth.user) {
      throw redirect({ to: '/dashboard' })
    }
  },
  component: LoginPage,
})

function LoginPage() {
  const { auth } = Route.useRouteContext()
  const [pending, setPending] = useState<'github' | 'google' | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function handleSignIn(provider: 'github' | 'google') {
    setPending(provider)
    setError(null)
    try {
      await auth.signInWithOAuth(provider)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed')
      setPending(null)
    }
  }

  return (
    <div className="mx-auto flex min-h-[60vh] max-w-md flex-col justify-center">
      <div
        className="rounded-xl border p-8 shadow-sm"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
      >
        <h1 className="text-2xl font-semibold tracking-tight">Sign in to Pindrop</h1>
        <p className="mt-2 text-sm" style={{ color: 'var(--muted-foreground)' }}>
          Connect your account to view your security dashboard.
        </p>

        <div className="mt-8 flex flex-col gap-3">
          <OAuthButton
            label="Continue with GitHub"
            icon={<Github className="size-4" />}
            pending={pending === 'github'}
            disabled={pending !== null}
            onClick={() => void handleSignIn('github')}
          />
          <OAuthButton
            label="Continue with Google"
            icon={<GoogleIcon />}
            pending={pending === 'google'}
            disabled={pending !== null}
            onClick={() => void handleSignIn('google')}
          />
        </div>

        {error ? (
          <p className="mt-4 text-sm text-red-600 dark:text-red-400" role="alert">
            {error}
          </p>
        ) : null}
      </div>
    </div>
  )
}

interface OAuthButtonProps {
  label: string
  icon: React.ReactNode
  pending: boolean
  disabled: boolean
  onClick: () => void
}

function OAuthButton({ label, icon, pending, disabled, onClick }: OAuthButtonProps) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={cn(
        'inline-flex h-11 w-full items-center justify-center gap-2 rounded-lg border text-sm font-medium transition-colors',
        'hover:bg-[var(--muted)] disabled:cursor-not-allowed disabled:opacity-60',
      )}
      style={{ borderColor: 'var(--border)' }}
    >
      {icon}
      {pending ? 'Redirecting…' : label}
    </button>
  )
}

function GoogleIcon() {
  return (
    <svg className="size-4" viewBox="0 0 24 24" aria-hidden>
      <path
        fill="currentColor"
        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"
      />
      <path
        fill="currentColor"
        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
      />
      <path
        fill="currentColor"
        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"
      />
      <path
        fill="currentColor"
        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
      />
    </svg>
  )
}
