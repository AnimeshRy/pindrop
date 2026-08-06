import { createContext, useContext } from 'react'

export interface AuthUser {
  id: string
  email: string
  name: string
  avatarUrl?: string
}

export interface AuthContextValue {
  enabled: boolean
  loading: boolean
  user: AuthUser | null
  signInWithGoogle: () => Promise<void>
  signInWithGithub: () => Promise<void>
  signOut: () => Promise<void>
}

export const AuthContext = createContext<AuthContextValue | null>(null)

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return ctx
}
