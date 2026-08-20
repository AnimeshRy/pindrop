/** User-facing theme preference stored in localStorage. */
export type ThemePreference = 'light' | 'dark' | 'system'

/** Resolved theme applied to the document. */
export type ResolvedTheme = 'light' | 'dark'

export const THEME_STORAGE_KEY = 'pindrop-theme'

/** Resolve a stored preference to the concrete light/dark value. */
export function resolveTheme(preference: ThemePreference): ResolvedTheme {
  if (preference === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  }
  return preference
}

/** Apply resolved theme to the document root for CSS token switching. */
export function applyTheme(resolved: ResolvedTheme): void {
  document.documentElement.dataset.theme = resolved
  document.documentElement.style.colorScheme = resolved
}

/** Read persisted preference from localStorage. */
export function readStoredPreference(): ThemePreference {
  const stored = localStorage.getItem(THEME_STORAGE_KEY)
  if (stored === 'light' || stored === 'dark' || stored === 'system') {
    return stored
  }
  return 'system'
}
