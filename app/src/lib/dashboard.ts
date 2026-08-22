/**
 * Aggregation helpers for the organization-wide overview page.
 *
 * The API has no aggregate endpoint yet — everything here is computed
 * client-side from `/api/v1/repos` plus, for the small set of repositories
 * that actually have runs, one `run` and one `findings` request each. That
 * is an N+1 by design rather than an oversight: a team's repo count is small
 * enough for this to be cheap, and it avoids inventing a server endpoint
 * before the shape of "org activity" has settled.
 */
import { getRun, listRunFindings, listStates, type Finding, type Repo, type Run } from '@/lib/api'
import { normalizeSeverity, normalizeStatus, SEVERITY_RANK, type Severity, type Status } from '@/lib/api'

export type SeverityCounts = Record<Severity, number>

const OPEN_STATUSES = new Set<Status>(['new', 'open', 'regressed'])
const RANK_TIERS: Severity[] = ['critical', 'high', 'medium', 'low']

/** Sums each repo's already-aggregated `open.bySeverity`, no extra fetches needed. */
export function aggregateSeverity(repos: Repo[]): SeverityCounts {
  const totals: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
  }
  for (const repo of repos) {
    const bySeverity = repo.open?.bySeverity ?? {}
    for (const [key, count] of Object.entries(bySeverity)) {
      const severity = normalizeSeverity(key)
      totals[severity] += count ?? 0
    }
  }
  return totals
}

export function openTotal(repos: Repo[]): number {
  return repos.reduce((sum, repo) => sum + (repo.open?.total ?? 0), 0)
}

/** A finding carried alongside the repository it was found in, for the org-wide table. */
export type RankedFinding = Finding & { repoId: string; repoName: string }

export interface RepoActivity {
  repo: Repo
  latestRun?: Run
  findings: RankedFinding[]
}

/**
 * Fetches each repo's last synced run (repo.lastRunId) and its findings, in
 * parallel. That matches repo.open and the lifecycle index; it is not always
 * the run with the latest finishedAt when older runs are synced later. A repo
 * with no runs yet, or a request that fails, contributes an empty activity
 * rather than aborting the whole dashboard.
 */
export async function fetchOrgActivity(
  token: string,
  repos: Repo[],
): Promise<RepoActivity[]> {
  return Promise.all(
    repos.map(async (repo): Promise<RepoActivity> => {
      if (!repo.lastRunId) {
        return { repo, findings: [] }
      }
      try {
        const latestRun = await getRun(token, repo.id, repo.lastRunId)
        const { findings } = await listRunFindings(token, repo.id, latestRun.id, {
          limit: 500,
        })
        return {
          repo,
          latestRun,
          findings: findings.map((finding) => ({
            ...finding,
            repoId: repo.id,
            repoName: repo.name,
          })),
        }
      } catch {
        return { repo, findings: [] }
      }
    }),
  )
}

/**
 * Loads every repo's open lifecycle states for the ranked-issues widget.
 * This matches the severity aggregates on `repo.open` — unlike paginated
 * run findings, which are sorted worst-first and would fill an 8-row table
 * with nothing but critical when one repo has many.
 */
export async function fetchOpenFindings(
  token: string,
  repos: Repo[],
): Promise<RankedFinding[]> {
  const batches = await Promise.all(
    repos.map(async (repo): Promise<RankedFinding[]> => {
      try {
        const states = await listStates(token, repo.id)
        return states
          .filter((state) => {
            const status = normalizeStatus(state.status)
            return status !== undefined && OPEN_STATUSES.has(status)
          })
          .map((state) => ({
            fingerprint: state.fingerprint,
            severity: state.severity,
            title: state.title,
            category: state.category,
            status: state.status,
            scanners: state.scanners,
            firstSeenAt: state.firstSeenAt,
            repoId: repo.id,
            repoName: repo.name,
          }))
      } catch {
        return []
      }
    }),
  )
  return batches.flat()
}

export interface DeltaTotals {
  new: number
  fixed: number
  regressed: number
}

/** Sums each repo's latest-run delta. A repo with no run contributes zero. */
export function deltaTotals(activities: RepoActivity[]): DeltaTotals {
  return activities.reduce(
    (totals, activity) => ({
      new: totals.new + (activity.latestRun?.delta.new ?? 0),
      fixed: totals.fixed + (activity.latestRun?.delta.fixed ?? 0),
      regressed: totals.regressed + (activity.latestRun?.delta.regressed ?? 0),
    }),
    { new: 0, fixed: 0, regressed: 0 },
  )
}

/** Open findings across the org, with representation from each severity band. */
export function rankedFindings(
  pool: RankedFinding[],
  limit: number,
): RankedFinding[] {
  const open = pool.filter((finding) => {
    const status = normalizeStatus(finding.status)
    return status !== undefined && OPEN_STATUSES.has(status)
  })

  const bySeverity = new Map<Severity, RankedFinding[]>()
  for (const finding of open) {
    const severity = normalizeSeverity(finding.severity)
    const bucket = bySeverity.get(severity) ?? []
    bucket.push(finding)
    bySeverity.set(severity, bucket)
  }

  // Spread slots across the four tiers users care about so one band cannot
  // consume the whole widget when hundreds of critical findings exist.
  const perTier = Math.max(1, Math.ceil(limit / RANK_TIERS.length))
  const picked: RankedFinding[] = []
  const used = new Set<string>()

  for (const tier of RANK_TIERS) {
    let tierCount = 0
    for (const finding of bySeverity.get(tier) ?? []) {
      if (tierCount >= perTier || picked.length >= limit) {
        break
      }
      const key = `${finding.repoId}:${finding.fingerprint}`
      if (used.has(key)) {
        continue
      }
      used.add(key)
      picked.push(finding)
      tierCount++
    }
  }

  if (picked.length < limit) {
    const rest = open
      .filter((finding) => !used.has(`${finding.repoId}:${finding.fingerprint}`))
      .sort(
        (a, b) =>
          SEVERITY_RANK[normalizeSeverity(b.severity)] -
          SEVERITY_RANK[normalizeSeverity(a.severity)],
      )
    for (const finding of rest) {
      if (picked.length >= limit) {
        break
      }
      picked.push(finding)
    }
  }

  return picked
}
