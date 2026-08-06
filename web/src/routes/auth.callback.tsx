import { createFileRoute, redirect, useNavigate } from '@tanstack/react-router'
import { useEffect } from 'react'

import { useAuth } from '@/lib/auth-context'
import { isCloudMode } from '@/lib/config'

export const Route = createFileRoute('/auth/callback')({
  beforeLoad: () => {
    if (!isCloudMode()) {
      throw redirect({ to: '/' })
    }
  },
  component: AuthCallbackPage,
})

function AuthCallbackPage() {
  const { loading, user } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    if (!loading && user) {
      void navigate({ to: '/' })
    }
  }, [loading, user, navigate])

  return (
    <div className="py-16 text-center">
      <p className="text-sm" style={{ color: 'var(--muted-foreground)' }}>
        Finishing sign-in…
      </p>
    </div>
  )
}
