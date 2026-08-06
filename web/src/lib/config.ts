/**
 * Runtime deployment settings from the Go server.
 *
 * Self-hosted binaries omit Supabase fields; cloud mode includes what the
 * browser needs to sign in.
 */

export type AppMode = 'self-hosted' | 'cloud'

export interface AppConfig {
  mode: AppMode
  supabaseUrl?: string
  publishableKey?: string
}

let appConfig: AppConfig = { mode: 'self-hosted' }

export function getAppConfig(): AppConfig {
  return appConfig
}

export function isCloudMode(): boolean {
  return appConfig.mode === 'cloud'
}

export async function loadAppConfig(): Promise<AppConfig> {
  const response = await fetch('/api/v1/config', {
    headers: { Accept: 'application/json' },
  })
  if (!response.ok) {
    throw new Error('Could not load app configuration from the server')
  }
  const body: unknown = await response.json()
  if (!body || typeof body !== 'object' || !('mode' in body)) {
    throw new Error('Server sent an invalid configuration response')
  }

  const mode = (body as { mode: string }).mode
  if (mode !== 'self-hosted' && mode !== 'cloud') {
    throw new Error(`Unknown deployment mode: ${mode}`)
  }

  appConfig = {
    mode,
    supabaseUrl:
      'supabaseUrl' in body &&
      typeof (body as { supabaseUrl: unknown }).supabaseUrl === 'string'
        ? (body as { supabaseUrl: string }).supabaseUrl
        : undefined,
    publishableKey:
      'publishableKey' in body &&
      typeof (body as { publishableKey: unknown }).publishableKey === 'string'
        ? (body as { publishableKey: string }).publishableKey
        : undefined,
  }
  return appConfig
}
