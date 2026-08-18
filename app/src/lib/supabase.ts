import { createClient } from '@supabase/supabase-js'

/** Strip accidental REST paths — auth lives at /auth/v1, not /rest/v1. */
function normalizeSupabaseUrl(url: string): string {
  return url.replace(/\/rest\/v1\/?$/i, '').replace(/\/+$/, '')
}

const supabaseUrl = normalizeSupabaseUrl(import.meta.env.VITE_SUPABASE_URL ?? '')
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY?.trim()

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error(
    'Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY. Copy app/.env.example to app/.env.local.',
  )
}

if (import.meta.env.VITE_SUPABASE_URL?.includes('/rest/v1')) {
  console.warn(
    '[pindrop] VITE_SUPABASE_URL should be the project base URL (https://xxx.supabase.co), not /rest/v1.',
  )
}

/**
 * Browser Supabase client. OAuth and session persistence are handled entirely
 * by Supabase Auth — the product backend only verifies the resulting JWT.
 */
export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    // PKCE is the default for browser OAuth; explicit for clarity.
    flowType: 'pkce',
    detectSessionInUrl: true,
    persistSession: true,
    autoRefreshToken: true,
  },
})
