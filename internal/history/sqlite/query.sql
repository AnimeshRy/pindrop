-- name: ListRepos :many
SELECT id, name, path, former_paths, origin, first_run_at, last_run_at, last_run_id
FROM repos
ORDER BY last_run_at DESC, id ASC;

-- name: GetRepo :one
SELECT id, name, path, former_paths, origin, first_run_at, last_run_at, last_run_id
FROM repos
WHERE id = ?;

-- name: GetRepoByPath :one
SELECT id, name, path, former_paths, origin, first_run_at, last_run_at, last_run_id
FROM repos
WHERE path = ?;

-- name: GetRepoByFormerPath :one
SELECT id, name, path, former_paths, origin, first_run_at, last_run_at, last_run_id
FROM repos
WHERE former_paths LIKE '%' || ? || '%';

-- name: UpsertRepo :exec
INSERT INTO repos (id, name, path, former_paths, origin, first_run_at, last_run_at, last_run_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    name = excluded.name,
    path = excluded.path,
    former_paths = excluded.former_paths,
    origin = excluded.origin,
    first_run_at = excluded.first_run_at,
    last_run_at = excluded.last_run_at,
    last_run_id = excluded.last_run_id;

-- name: DeleteRepo :exec
DELETE FROM repos WHERE id = ?;

-- name: ListRepoIDs :many
SELECT id FROM repos;

-- name: ListRunsByRepo :many
SELECT id, repo_id, prev_run_id, started_at, finished_at, duration_ms,
       tool_name, tool_version, vcs_origin, vcs_branch, vcs_commit,
       scanners, scope_hash, counts, delta, unreadable, problem, document
FROM runs
WHERE repo_id = ?
ORDER BY id ASC;

-- name: GetRun :one
SELECT id, repo_id, prev_run_id, started_at, finished_at, duration_ms,
       tool_name, tool_version, vcs_origin, vcs_branch, vcs_commit,
       scanners, scope_hash, counts, delta, unreadable, problem, document
FROM runs
WHERE repo_id = ? AND id = ?;

-- name: GetNewestRunID :one
SELECT id FROM runs
WHERE repo_id = ?
ORDER BY id DESC
LIMIT 1;

-- name: InsertRun :exec
INSERT INTO runs (
    id, repo_id, prev_run_id, started_at, finished_at, duration_ms,
    tool_name, tool_version, vcs_origin, vcs_branch, vcs_commit,
    scanners, scope_hash, counts, delta, unreadable, problem, document
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteRuns :exec
DELETE FROM runs WHERE repo_id = ? AND id IN (sqlc.slice('ids'));

-- name: ListFindingsByRun :many
SELECT id, run_id, repo_id, fingerprint, scanner, scanners, rule_id, aliases,
       category, severity, title, message, location_path, location_start_line,
       location_end_line, location_snippet, package_name, package_version,
       package_ecosystem, package_purl, fixed_in, refs, status
FROM findings
WHERE run_id = ?
ORDER BY id ASC;

-- name: InsertFinding :exec
INSERT INTO findings (
    run_id, repo_id, fingerprint, scanner, scanners, rule_id, aliases,
    category, severity, title, message, location_path, location_start_line,
    location_end_line, location_snippet, package_name, package_version,
    package_ecosystem, package_purl, fixed_in, refs, status
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListFindingStates :many
SELECT repo_id, fingerprint, status, severity, category, title, scanners,
       first_seen_at, last_seen_at, first_run, last_run, fixed_at, fixed_run,
       occurrences, regressions
FROM finding_states
WHERE repo_id = ?;

-- name: UpsertFindingState :exec
INSERT INTO finding_states (
    repo_id, fingerprint, status, severity, category, title, scanners,
    first_seen_at, last_seen_at, first_run, last_run, fixed_at, fixed_run,
    occurrences, regressions
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(repo_id, fingerprint) DO UPDATE SET
    status = excluded.status,
    severity = excluded.severity,
    category = excluded.category,
    title = excluded.title,
    scanners = excluded.scanners,
    first_seen_at = excluded.first_seen_at,
    last_seen_at = excluded.last_seen_at,
    first_run = excluded.first_run,
    last_run = excluded.last_run,
    fixed_at = excluded.fixed_at,
    fixed_run = excluded.fixed_run,
    occurrences = excluded.occurrences,
    regressions = excluded.regressions;

-- name: UpdateRunDerived :exec
UPDATE runs SET
    prev_run_id = ?,
    counts = ?,
    delta = ?,
    unreadable = ?,
    problem = ?,
    document = ?
WHERE repo_id = ? AND id = ?;

-- name: DeleteFindingStatesByRepo :exec
DELETE FROM finding_states WHERE repo_id = ?;
