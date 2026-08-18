import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import type { Provider, Session, User } from '@supabase/supabase-js'

import { supabase } from '@/lib/supabase'

/** Values exposed to routes and components through React context. */
export interface AuthContextValue {
  user: User | null
  session: Session | null
  /** True until the initial session has been read from storage. */
  loading: boolean
  signInWithOAuth: (provider: Provider) => Promise<void>
  signOut: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

/** Read auth state. Must be used inside [AuthProvider]. */
export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (!value) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return value
}

interface AuthProviderProps {
  children: ReactNode
}

/**
 * Tracks Supabase session state and exposes sign-in / sign-out helpers.
 *
 * Session restoration happens once on mount; `onAuthStateChange` keeps the
 * context in sync after OAuth redirects and token refresh.
 */
export function AuthProvider({ children }: AuthProviderProps) {
  const [session, setSession] = useState<Session | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true

    // Restore session from local storage before rendering protected routes.
    void supabase.auth.getSession().then(({ data }) => {
      if (mounted) {
        setSession(data.session)
        setLoading(false)
      }
    })

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession)
      setLoading(false)
    })

    return () => {
      mounted = false
      subscription.unsubscribe()
    }
  }, [])

  const signInWithOAuth = useCallback(async (provider: Provider) => {
    const redirectTo = `${window.location.origin}/dashboard`
    const { error } = await supabase.auth.signInWithOAuth({
      provider,
      options: { redirectTo },
    })
    if (error) {
      throw error
    }
  }, [])

  const signOut = useCallback(async () => {
    const { error } = await supabase.auth.signOut()
    if (error) {
      throw error
    }
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({
      user: session?.user ?? null,
      session,
      loading,
      signInWithOAuth,
      signOut,
    }),
    [session, loading, signInWithOAuth, signOut],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
