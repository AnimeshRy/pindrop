import { createFileRoute, redirect } from '@tanstack/react-router'
import { useState } from 'react'

import { useAuth } from '@/lib/auth-context'
import { isCloudMode } from '@/lib/config'

export const Route = createFileRoute('/login')({
  beforeLoad: () => {
    if (!isCloudMode()) {
      throw redirect({ to: '/' })
    }
  },
  component: LoginPage,
})

function LoginPage() {
  const { signInWithGoogle, signInWithGithub } = useAuth()
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<'google' | 'github' | null>(null)

  const params = new URLSearchParams(window.location.search)
  const oauthError = params.get('error_description') ?? params.get('error')

  async function start(provider: 'google' | 'github') {
    setError(null)
    setBusy(provider)
    try {
      if (provider === 'google') {
        await signInWithGoogle()
      } else {
        await signInWithGithub()
      }
    } catch (err) {
      setBusy(null)
      setError(err instanceof Error ? err.message : 'Sign-in failed — try again')
    }
  }

  return (
    <div className="mx-auto flex min-h-[60vh] max-w-md flex-col justify-center">
      <h1 className="text-xl font-semibold">Sign in to Pindrop</h1>
      <p className="mt-2 text-sm" style={{ color: 'var(--muted-foreground)' }}>
        Use Google or GitHub to access your cloud dashboard.
      </p>

      <div className="mt-8 space-y-3">
        <button
          type="button"
          disabled={busy !== null}
          className="w-full rounded-lg border px-4 py-2.5 text-sm font-medium disabled:opacity-60"
          style={{ borderColor: 'var(--border)' }}
          onClick={() => void start('google')}
        >
          {busy === 'google' ? 'Redirecting…' : 'Continue with Google'}
        </button>
        <button
          type="button"
          disabled={busy !== null}
          className="w-full rounded-lg border px-4 py-2.5 text-sm font-medium disabled:opacity-60"
          style={{ borderColor: 'var(--border)' }}
          onClick={() => void start('github')}
        >
          {busy === 'github' ? 'Redirecting…' : 'Continue with GitHub'}
        </button>
      </div>

      {(oauthError || error) && (
        <p
          className="mt-4 text-sm"
          role="alert"
          style={{ color: 'var(--destructive, #b91c1c)' }}
        >
          {oauthError ?? error}
        </p>
      )}
    </div>
  )
}
