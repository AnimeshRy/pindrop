import { createClient, type SupabaseClient } from '@supabase/supabase-js'

import { getAppConfig, isCloudMode } from '@/lib/config'

let client: SupabaseClient | null = null

export function getSupabaseClient(): SupabaseClient | null {
  if (!isCloudMode()) {
    return null
  }
  if (client) {
    return client
  }

  const cfg = getAppConfig()
  if (!cfg.supabaseUrl || !cfg.publishableKey) {
    throw new Error(
      'Cloud mode is missing Supabase settings — set PINDROP_SUPABASE_URL and PINDROP_SUPABASE_PUBLISHABLE_KEY on the server',
    )
  }

  client = createClient(cfg.supabaseUrl, cfg.publishableKey, {
    auth: {
      flowType: 'pkce',
      detectSessionInUrl: true,
      persistSession: true,
      autoRefreshToken: true,
    },
  })
  return client
}

export function resetSupabaseClientForTests(): void {
  client = null
}
