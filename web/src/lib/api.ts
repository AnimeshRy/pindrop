/**
 * Client for the Pindrop API.
 *
 * These types mirror the Go structs in internal/scan and internal/report. They
 * are hand-maintained for now; once the server grows a protobuf or OpenAPI
 * schema they should be generated instead.
 */

export const SEVERITIES = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
  'unknown',
] as const

export type Severity = (typeof SEVERITIES)[number]

export const CATEGORIES = [
  'vulnerability',
  'secret',
  'misconfiguration',
  'code',
  'license',
] as const

export type Category = (typeof CATEGORIES)[number]

export interface Location {
  path: string
  startLine?: number
  endLine?: number
  snippet?: string
}

export interface PackageRef {
  name: string
  version?: string
  ecosystem?: string
  purl?: string
}

export interface Finding {
  fingerprint: string
  scanner: string
  /**
   * Every adapter that reported this finding, populated by cross-tool dedup.
   * Its length is a confidence signal — two independent tools agreeing is
   * stronger evidence than one asserting — and it is absent until findings are
   * merged, so read it as `scanners?.length ?? 1`.
   */
  scanners?: string[]
  ruleId: string
  /** Other identifiers for the same advisory, e.g. the CVE for a GHSA. */
  aliases?: string[]
  category: Category
  severity: Severity
  title: string
  message?: string
  location: Location
  package?: PackageRef
  fixedIn?: string
  references?: string[]
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
 * User-facing wording for each status.
 *
 * "no longer detected" rather than "fixed" is deliberate and load-bearing. A
 * scanner ceasing to report something is a weaker claim than a fix: the rule
 * may have changed, the file may have moved, the scanner may not have run over
 * it. Overstating that is how a security tool teaches people to distrust it.
 */
export const STATUS_LABEL: Record<Status, string> = {
  new: 'new',
  open: 'still open',
  fixed: 'no longer detected',
  regressed: 'returned',
}

/** A finding paired with its status in the run being viewed. */
export type FindingWithStatus = Finding & { status: Status }

export interface ScanSummary {
  scanner: string
  target: string
  startedAt: string
  durationMs: number
  findings: number
}

export interface Summary {
  total: number
  bySeverity: Partial<Record<Severity, number>>
  byCategory: Partial<Record<Category, number>>
  scans: ScanSummary[]
  generatedAt: string
}

interface FindingsResponse {
  findings: Finding[]
  total: number
}

/* -------------------------------------------------------------------------
 * Scan history
 * ---------------------------------------------------------------------- */

/** A tally of findings, mirroring history.Counts. */
export interface Counts {
  total: number
  bySeverity?: Partial<Record<Severity, number>>
  byCategory?: Partial<Record<Category, number>>
}

/**
 * What one run changed, mirroring history.DeltaCounts.
 *
 * The four numbers deliberately do not have to add up to a run's total: a
 * finding nobody could observe — because its scanner did not run, or the
 * exclusions changed — is counted in none of them.
 */
export interface DeltaCounts {
  new: number
  stillOpen: number
  fixed: number
  regressed: number
}

/** Version-control state a run was taken at. */
export interface RunVCS {
  origin?: string
  branch?: string
  commit?: string
}

export interface Tool {
  name: string
  version: string
}

/** One repository's history summary, mirroring history.Repo. */
export interface Repo {
  id: string
  name: string
  /** Where it was last scanned. Display metadata, never identity. */
  path: string
  formerPaths?: string[]
  origin?: string
  firstRunAt: string
  lastRunAt: string
  lastRun: string
  runs: number
  open: Counts
  /** The checkout is gone from disk. The history is still worth reading. */
  missing?: boolean
}

/** One recorded scan's metadata, mirroring history.Run. */
export interface Run {
  id: string
  repoId: string
  prevRun?: string
  startedAt: string
  finishedAt: string
  durationMs: number
  tool: Tool
  vcs?: RunVCS
  scanners?: ScanSummary[]
  scopeHash?: string
  counts: Counts
  delta: DeltaCounts
  /** The run's file is corrupt or was written by a newer Pindrop. */
  unreadable?: boolean
  problem?: string
}

/** One fingerprint's whole life in one repository, mirroring history.FindingState. */
export interface FindingState {
  fingerprint: string
  status: Status
  severity: Severity
  category: Category
  title: string
  scanners?: string[]
  firstSeenAt: string
  lastSeenAt: string
  firstRun: string
  lastRun: string
  fixedAt?: string
  fixedRun?: string
  occurrences: number
  regressions: number
}

/** The result of comparing two runs, mirroring history.Diff. */
export interface Diff {
  base?: string
  head: string
  counts: DeltaCounts
  new: Finding[] | null
  stillOpen: Finding[] | null
  fixed: Finding[] | null
  regressed: Finding[] | null
}

export interface RunSummary {
  total: number
  bySeverity: Partial<Record<Severity, number>>
  byCategory: Partial<Record<Category, number>>
}

interface ReposResponse {
  repos: Repo[]
  total: number
}

interface RunsResponse {
  runs: Run[]
  total: number
  /** Cursor for the next page, or '' when this is the last one. */
  nextBefore: string
}

interface RunDetailResponse {
  run: Run
  summary: RunSummary
}

interface RunFindingsResponse {
  findings: FindingWithStatus[]
  total: number
}

interface StatesResponse {
  states: FindingState[]
  total: number
}

/** Options for listing a repository's runs. */
export interface RunListOptions {
  branch?: string
  since?: string
  until?: string
  before?: string
  limit?: number
}

/** Rank used for sorting; mirrors Severity.Rank in the Go domain model. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  unknown: 0,
}

/**
 * ApiError carries the server's message so the UI can show what actually went
 * wrong — usually "no scan report yet", which is a setup step rather than a
 * failure.
 */
export class ApiError extends Error {
  // Declared explicitly rather than as a constructor parameter property:
  // `erasableSyntaxOnly` rejects that form, since it emits runtime code and so
  // cannot be stripped by a type-only transform.
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    headers: { Accept: 'application/json' },
  })

  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null)
    const message =
      body && typeof body === 'object' && 'error' in body
        ? String((body as { error: unknown }).error)
        : `Request failed with status ${response.status}`
    throw new ApiError(message, response.status)
  }

  return response.json() as Promise<T>
}

export async function fetchFindings(): Promise<Finding[]> {
  const data = await request<FindingsResponse>('/api/v1/findings')
  return data.findings
}

export async function fetchSummary(): Promise<Summary> {
  return request<Summary>('/api/v1/summary')
}

/**
 * Repository IDs are validated server-side and 404 if malformed, but they are
 * still encoded here: a path segment built by string concatenation is exactly
 * how a traversal reaches a server in the first place.
 */
function repoPath(repoId: string, suffix = ''): string {
  return `/api/v1/repos/${encodeURIComponent(repoId)}${suffix}`
}

function runPath(repoId: string, runId: string, suffix = ''): string {
  return repoPath(repoId, `/runs/${encodeURIComponent(runId)}${suffix}`)
}

/** Build a query string from defined values only, so `?limit=undefined` cannot happen. */
function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') {
      search.set(key, String(value))
    }
  }
  const encoded = search.toString()
  return encoded ? `?${encoded}` : ''
}

export async function fetchRepos(): Promise<Repo[]> {
  const data = await request<ReposResponse>('/api/v1/repos')
  return data.repos
}

export async function fetchRepo(repoId: string): Promise<Repo> {
  return request<Repo>(repoPath(repoId))
}

export async function fetchRuns(
  repoId: string,
  options: RunListOptions = {},
): Promise<RunsResponse> {
  return request<RunsResponse>(repoPath(repoId, '/runs') + query({ ...options }))
}

export async function fetchRun(
  repoId: string,
  runId: string,
): Promise<RunDetailResponse> {
  return request<RunDetailResponse>(runPath(repoId, runId))
}

export async function fetchRunFindings(
  repoId: string,
  runId: string,
): Promise<FindingWithStatus[]> {
  const data = await request<RunFindingsResponse>(runPath(repoId, runId, '/findings'))
  return data.findings
}

export async function fetchRunDiff(
  repoId: string,
  runId: string,
  against?: string,
): Promise<Diff> {
  return request<Diff>(runPath(repoId, runId, '/diff') + query({ against }))
}

export async function fetchStates(repoId: string): Promise<FindingState[]> {
  const data = await request<StatesResponse>(repoPath(repoId, '/states'))
  return data.states
}
