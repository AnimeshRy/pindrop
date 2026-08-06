import type { Session, User } from '@supabase/supabase-js'
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'

import { primeInitialSession, waitForInitialSession } from '@/lib/auth-bootstrap'
import { AuthContext, type AuthUser } from '@/lib/auth-context'
import { setAccessToken, setUnauthorizedHandler } from '@/lib/auth-token'
import { isCloudMode } from '@/lib/config'
import { getSupabaseClient } from '@/lib/supabase'

function userFromSupabase(user: User): AuthUser {
  const meta = user.user_metadata
  const fullName =
    typeof meta.full_name === 'string'
      ? meta.full_name
      : typeof meta.name === 'string'
        ? meta.name
        : (user.email ?? user.id)

  const avatar =
    typeof meta.avatar_url === 'string'
      ? meta.avatar_url
      : typeof meta.picture === 'string'
        ? meta.picture
        : undefined

  return {
    id: user.id,
    email: user.email ?? '',
    name: fullName,
    avatarUrl: avatar,
  }
}

function applySession(
  session: Session | null,
  setUser: (user: AuthUser | null) => void,
  setLoading: (loading: boolean) => void,
) {
  setAccessToken(session?.access_token ?? null)
  setUser(session?.user ? userFromSupabase(session.user) : null)
  setLoading(false)
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const enabled = isCloudMode()
  const [loading, setLoading] = useState(enabled)
  const [user, setUser] = useState<AuthUser | null>(null)

  useEffect(() => {
    if (!enabled) {
      return
    }

    const supabase = getSupabaseClient()
    if (!supabase) {
      queueMicrotask(() => setLoading(false))
      return
    }

    primeInitialSession()

    void waitForInitialSession().then((session) => {
      applySession(session, setUser, setLoading)
    })

    setUnauthorizedHandler(() => {
      void supabase.auth.signOut()
      setAccessToken(null)
      setUser(null)
      window.location.assign('./login')
    })

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      applySession(session, setUser, setLoading)
    })

    return () => {
      subscription.unsubscribe()
    }
  }, [enabled])

  const signInWithOAuth = useCallback(async (provider: 'google' | 'github') => {
    const supabase = getSupabaseClient()
    if (!supabase) {
      throw new Error('Sign-in is only available in cloud mode')
    }
    const redirectTo = `${window.location.origin}/auth/callback`
    const { error } = await supabase.auth.signInWithOAuth({
      provider,
      options: { redirectTo },
    })
    if (error) {
      throw error
    }
  }, [])

  const signInWithGoogle = useCallback(async () => {
    await signInWithOAuth('google')
  }, [signInWithOAuth])

  const signInWithGithub = useCallback(async () => {
    await signInWithOAuth('github')
  }, [signInWithOAuth])

  const signOut = useCallback(async () => {
    const supabase = getSupabaseClient()
    if (!supabase) {
      return
    }
    await supabase.auth.signOut()
    setAccessToken(null)
    setUser(null)
    if (isCloudMode()) {
      window.location.assign('./login')
    }
  }, [])

  const value = useMemo(
    () => ({
      enabled,
      loading,
      user,
      signInWithGoogle,
      signInWithGithub,
      signOut,
    }),
    [enabled, loading, user, signInWithGoogle, signInWithGithub, signOut],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
