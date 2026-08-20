import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'

import { ThemeContext } from '@/lib/theme-context'
import {
  applyTheme,
  readStoredPreference,
  resolveTheme,
  THEME_STORAGE_KEY,
  type ResolvedTheme,
  type ThemePreference,
} from '@/lib/theme'

interface ThemeProviderProps {
  children: ReactNode
}

/**
 * Persists theme preference and keeps `data-theme` in sync with system changes
 * while the user is on the "system" setting.
 */
export function ThemeProvider({ children }: ThemeProviderProps) {
  const [preference, setPreferenceState] = useState<ThemePreference>(() =>
    readStoredPreference(),
  )
  const [resolved, setResolved] = useState<ResolvedTheme>(() =>
    resolveTheme(readStoredPreference()),
  )

  const setPreference = useCallback((next: ThemePreference) => {
    setPreferenceState(next)
    localStorage.setItem(THEME_STORAGE_KEY, next)
    const nextResolved = resolveTheme(next)
    setResolved(nextResolved)
    applyTheme(nextResolved)
  }, [])

  useEffect(() => {
    applyTheme(resolved)
  }, [resolved])

  useEffect(() => {
    if (preference !== 'system') {
      return
    }

    const media = window.matchMedia('(prefers-color-scheme: dark)')

    function handleChange(): void {
      const nextResolved = resolveTheme('system')
      setResolved(nextResolved)
      applyTheme(nextResolved)
    }

    media.addEventListener('change', handleChange)
    return () => media.removeEventListener('change', handleChange)
  }, [preference])

  const value = useMemo(
    () => ({ preference, resolved, setPreference }),
    [preference, resolved, setPreference],
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}
