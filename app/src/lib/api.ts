/**
 * Client for the Pindrop SaaS API (`server/`).
 *
 * Requests go through the Vite dev proxy at `/api` in development. Types mirror
 * the Go structs in server/internal/syncstore.
 */

export type RepoSource = 'cli' | 'github' | 'bitbucket'

export const SOURCE_LABEL: Record<RepoSource, string> = {
  cli: 'Local sync',
  github: 'GitHub',
  bitbucket: 'Bitbucket',
}

export const SEVERITIES = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
  'unknown',
] as const

export type Severity = (typeof SEVERITIES)[number]

/** Rank used for sorting; higher is worse. Mirrors Severity.Rank in the Go domain model. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
}

/** A finding's severity as reported can be missing or an unrecognized string; this is never undefined. */
export function normalizeSeverity(value?: string): Severity {
  const lower = value?.toLowerCase()
  return (SEVERITIES as readonly string[]).includes(lower ?? '')
    ? (lower as Severity)
    : 'unknown'
}

/**
 * Where a finding sits in its lifecycle, mirroring scan.Status.
 *
 * `fixed` is the Go constant's name and must stay that way on the wire, but it
 * is never the word shown to a user — see STATUS_LABEL.
 */
export const STATUSES = ['new', 'open', 'fixed', 'regressed'] as const

export type Status = (typeof STATUSES)[number]

/**
 * User-facing wording for each status. "no longer detected" rather than
 * "fixed" is deliberate: a scanner ceasing to report something is a weaker
 * claim than a fix, and overstating it teaches people to distrust the tool.
 */
export const STATUS_LABEL: Record<Status, string> = {
  new: 'new',
  open: 'still open',
  fixed: 'no longer detected',
  regressed: 'returned',
}

export function normalizeStatus(value?: string): Status | undefined {
  const lower = value?.toLowerCase()
  return (STATUSES as readonly string[]).includes(lower ?? '')
    ? (lower as Status)
    : undefined
}

export interface Counts {
  total: number
  bySeverity?: Record<string, number>
  byCategory?: Record<string, number>
}

export interface RepoLink {
  id: string
  orgId: string
  repoId: string
  source: RepoSource
  externalId: string
  path?: string
  formerPaths?: string[]
  metadata?: Record<string, unknown>
  firstSyncedAt: string
  lastSyncedAt: string
}

export interface Repo {
  id: string
  orgId: string
  name: string
  origin?: string
  lastRunId?: string
  firstSyncedAt: string
  lastSyncedAt: string
  createdAt: string
  runs?: number
  open?: Counts
  links?: RepoLink[]
}

export interface RunVCS {
  origin?: string
  branch?: string
  commit?: string
}

export interface ScanSummary {
  scanner: string
  findings?: number
  durationMs?: number
  error?: string
}

export interface DeltaCounts {
  new: number
  stillOpen: number
  fixed: number
  regressed: number
}

export interface Run {
  id: string
  orgId: string
  repoId: string
  source: RepoSource
  clientRunId: string
  prevRunId?: string
  startedAt: string
  finishedAt: string
  durationMs: number
  toolName?: string
  toolVersion?: string
  vcs?: RunVCS
  scanners?: ScanSummary[]
  scopeHash?: string
  counts: Counts
  delta: DeltaCounts
  unreadable?: boolean
  problem?: string
  syncedAt: string
}

export interface Finding {
  fingerprint: string
  scanner?: string
  scanners?: string[]
  ruleId?: string
  aliases?: string[]
  category?: string
  severity?: string
  title?: string
  message?: string
  locationPath?: string
  locationStartLine?: number
  locationEndLine?: number
  locationSnippet?: string
  packageName?: string
  packageVersion?: string
  packageEcosystem?: string
  packagePurl?: string
  fixedIn?: string
  refs?: string[]
  status?: string
  /** When the issue was first seen in this repo's lifecycle index. */
  firstSeenAt?: string
}

export interface FindingListParams {
  severity?: string
  category?: string
  status?: string
  /** Free-text search across title, message, rule, and path. */
  q?: string
  limit?: number
  offset?: number
}

export interface FindingListResponse {
  findings: Finding[]
  total: number
}

/** Lifecycle index entry for one fingerprint in a repository. */
export interface FindingState {
  fingerprint: string
  status: string
  severity?: string
  category?: string
  title?: string
  scanners?: string[]
  firstSeenAt: string
  lastSeenAt: string
  firstRun?: string
  lastRun?: string
  fixedAt?: string
  fixedRun?: string
  occurrences?: number
  regressions?: number
}

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

/** Authenticated fetch against the product API. */
export async function apiFetch<T>(
  path: string,
  accessToken: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Authorization', `Bearer ${accessToken}`)
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const res = await fetch(path, { ...init, headers })
  if (!res.ok) {
    let message = res.statusText
    try {
      const payload = (await res.json()) as { error?: string }
      if (payload.error) {
        message = payload.error
      }
    } catch {
      // Non-JSON error body — keep statusText.
    }
    throw new ApiError(res.status, message)
  }
  if (res.status === 204) {
    return undefined as T
  }
  return (await res.json()) as T
}

export function listRepos(accessToken: string, source?: RepoSource): Promise<Repo[]> {
  const qs = source ? `?source=${encodeURIComponent(source)}` : ''
  return apiFetch<Repo[]>(`/api/v1/repos${qs}`, accessToken)
}

export function getRepo(accessToken: string, repoId: string): Promise<Repo> {
  return apiFetch<Repo>(`/api/v1/repos/${encodeURIComponent(repoId)}`, accessToken)
}

export function listRuns(accessToken: string, repoId: string): Promise<Run[]> {
  return apiFetch<Run[]>(
    `/api/v1/repos/${encodeURIComponent(repoId)}/runs`,
    accessToken,
  )
}

export function getRun(accessToken: string, repoId: string, runId: string): Promise<Run> {
  return apiFetch<Run>(
    `/api/v1/repos/${encodeURIComponent(repoId)}/runs/${encodeURIComponent(runId)}`,
    accessToken,
  )
}

export function listRunFindings(
  accessToken: string,
  repoId: string,
  runId: string,
  params: FindingListParams = {},
): Promise<FindingListResponse> {
  const qs = new URLSearchParams()
  if (params.severity) {
    qs.set('severity', params.severity)
  }
  if (params.category) {
    qs.set('category', params.category)
  }
  if (params.status) {
    qs.set('status', params.status)
  }
  if (params.q) {
    qs.set('q', params.q)
  }
  if (params.limit !== undefined) {
    qs.set('limit', String(params.limit))
  }
  if (params.offset !== undefined) {
    qs.set('offset', String(params.offset))
  }
  const query = qs.toString()
  return apiFetch<FindingListResponse>(
    `/api/v1/repos/${encodeURIComponent(repoId)}/runs/${encodeURIComponent(runId)}/findings${query ? `?${query}` : ''}`,
    accessToken,
  )
}

export function listStates(accessToken: string, repoId: string): Promise<FindingState[]> {
  return apiFetch<FindingState[]>(
    `/api/v1/repos/${encodeURIComponent(repoId)}/states`,
    accessToken,
  )
}
