import type { Session } from '@supabase/supabase-js'

import { isCloudMode } from '@/lib/config'
import { getSupabaseClient } from '@/lib/supabase'

let initialSessionPromise: Promise<Session | null> | null = null

export function waitForInitialSession(): Promise<Session | null> {
  return initialSessionPromise ?? Promise.resolve(null)
}

/** Call before the router mounts so beforeLoad can await the Supabase session. */
export function primeInitialSession(): void {
  if (!isCloudMode()) {
    initialSessionPromise = Promise.resolve(null)
    return
  }
  const supabase = getSupabaseClient()
  if (!supabase) {
    initialSessionPromise = Promise.resolve(null)
    return
  }
  initialSessionPromise = supabase.auth.getSession().then(({ data }) => data.session)
}

export function resetInitialSessionForTests(): void {
  initialSessionPromise = null
}
