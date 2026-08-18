import { createFileRoute, redirect, useRouter } from '@tanstack/react-router'
import { LogOut } from 'lucide-react'
import { useState } from 'react'

import { cn } from '@/lib/utils'

export const Route = createFileRoute('/dashboard')({
  beforeLoad: ({ context }) => {
    if (context.auth.loading) {
      return
    }
    if (!context.auth.user) {
      throw redirect({ to: '/login' })
    }
  },
  component: DashboardPage,
})

function DashboardPage() {
  const { auth } = Route.useRouteContext()
  const router = useRouter()
  const [signingOut, setSigningOut] = useState(false)

  const user = auth.user
  if (!user) {
    return null
  }

  const displayName =
    (user.user_metadata.full_name as string | undefined) ??
    (user.user_metadata.name as string | undefined) ??
    user.email ??
    'User'

  const avatarUrl =
    (user.user_metadata.avatar_url as string | undefined) ??
    (user.user_metadata.picture as string | undefined)

  async function handleSignOut() {
    setSigningOut(true)
    try {
      await auth.signOut()
      await router.navigate({ to: '/login' })
    } finally {
      setSigningOut(false)
    }
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--muted-foreground)' }}>
            Welcome back. Your scan history and triage tools will appear here.
          </p>
        </div>

        <button
          type="button"
          disabled={signingOut}
          onClick={() => void handleSignOut()}
          className={cn(
            'inline-flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-medium transition-colors',
            'hover:bg-[var(--muted)] disabled:cursor-not-allowed disabled:opacity-60',
          )}
          style={{ borderColor: 'var(--border)' }}
        >
          <LogOut className="size-4" />
          {signingOut ? 'Signing out…' : 'Log out'}
        </button>
      </div>

      <section
        className="rounded-xl border p-6"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
      >
        <h2 className="text-sm font-medium uppercase tracking-wide text-[var(--muted-foreground)]">
          Account
        </h2>

        <div className="mt-4 flex items-center gap-4">
          {avatarUrl ? (
            <img
              src={avatarUrl}
              alt=""
              className="size-12 rounded-full border object-cover"
              style={{ borderColor: 'var(--border)' }}
            />
          ) : (
            <div
              className="flex size-12 items-center justify-center rounded-full border text-lg font-medium"
              style={{ borderColor: 'var(--border)', backgroundColor: 'var(--muted)' }}
            >
              {displayName.charAt(0).toUpperCase()}
            </div>
          )}

          <div>
            <p className="font-medium">{displayName}</p>
            {user.email ? (
              <p className="text-sm" style={{ color: 'var(--muted-foreground)' }}>
                {user.email}
              </p>
            ) : null}
          </div>
        </div>
      </section>

      <section
        className="rounded-xl border border-dashed p-8 text-center"
        style={{ borderColor: 'var(--border)' }}
      >
        <p className="text-sm" style={{ color: 'var(--muted-foreground)' }}>
          Scan results, repositories, and triage will land here in a future release.
        </p>
      </section>
    </div>
  )
}
