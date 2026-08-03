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
  ruleId: string
  category: Category
  severity: Severity
  title: string
  message?: string
  location: Location
  package?: PackageRef
  fixedIn?: string
  references?: string[]
}

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
