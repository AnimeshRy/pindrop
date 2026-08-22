-- name: UpsertUser :exec
INSERT INTO users (id, email)
VALUES ($1, $2)
ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email;

-- name: CreateOrg :one
INSERT INTO orgs (name)
VALUES ($1)
RETURNING id, name, created_at;

-- name: AddOrgMember :exec
INSERT INTO org_members (org_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;

-- name: GetPersonalOrgForUser :one
SELECT o.id, o.name, o.created_at
FROM orgs o
JOIN org_members m ON m.org_id = o.id
WHERE m.user_id = $1 AND m.role = 'owner'
ORDER BY o.created_at ASC
LIMIT 1;

-- name: GetRepoByOrigin :one
SELECT id, org_id, name, origin, last_run_id, first_synced_at, last_synced_at, created_at
FROM repos
WHERE org_id = $1 AND origin = $2 AND origin <> ''
LIMIT 1;

-- name: InsertRepo :one
INSERT INTO repos (org_id, name, origin, last_run_id, first_synced_at, last_synced_at)
VALUES ($1, $2, $3, $4, now(), now())
RETURNING id, org_id, name, origin, last_run_id, first_synced_at, last_synced_at, created_at;

-- name: UpdateRepoSynced :exec
UPDATE repos
SET name = $3,
    origin = $4,
    last_run_id = $5,
    last_synced_at = now()
WHERE org_id = $1 AND id = $2;

-- name: TouchRepoLastRun :exec
UPDATE repos
SET last_run_id = $3,
    last_synced_at = now()
WHERE org_id = $1 AND id = $2;

-- name: GetRepoByID :one
SELECT id, org_id, name, origin, last_run_id, first_synced_at, last_synced_at, created_at
FROM repos
WHERE org_id = $1 AND id = $2;

-- name: ListReposByOrg :many
SELECT id, org_id, name, origin, last_run_id, first_synced_at, last_synced_at, created_at
FROM repos
WHERE org_id = $1
ORDER BY last_synced_at DESC;

-- name: UpsertRepoLink :one
INSERT INTO repo_links (
    org_id, repo_id, source, external_id, path, former_paths, metadata,
    first_synced_at, last_synced_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
ON CONFLICT (org_id, source, external_id) DO UPDATE SET
    repo_id = EXCLUDED.repo_id,
    path = EXCLUDED.path,
    former_paths = EXCLUDED.former_paths,
    metadata = EXCLUDED.metadata,
    last_synced_at = now()
RETURNING id, org_id, repo_id, source, external_id, path, former_paths, metadata,
          first_synced_at, last_synced_at;

-- name: GetRepoLinkByExternal :one
SELECT id, org_id, repo_id, source, external_id, path, former_paths, metadata,
       first_synced_at, last_synced_at
FROM repo_links
WHERE org_id = $1 AND source = $2 AND external_id = $3;

-- name: ListRepoLinksByRepo :many
SELECT id, org_id, repo_id, source, external_id, path, former_paths, metadata,
       first_synced_at, last_synced_at
FROM repo_links
WHERE org_id = $1 AND repo_id = $2
ORDER BY last_synced_at DESC;

-- name: ListRepoLinksByOrg :many
SELECT id, org_id, repo_id, source, external_id, path, former_paths, metadata,
       first_synced_at, last_synced_at
FROM repo_links
WHERE org_id = $1
ORDER BY last_synced_at DESC;

-- name: GetRunByClientID :one
SELECT id, org_id, repo_id, source, client_run_id, prev_run_id, started_at, finished_at,
       duration_ms, tool_name, tool_version, vcs_origin, vcs_branch, vcs_commit,
       scanners, scope_hash, counts, delta, unreadable, problem, document, synced_at
FROM runs
WHERE repo_id = $1 AND client_run_id = $2;

-- name: UpsertRun :one
INSERT INTO runs (
    org_id, repo_id, source, client_run_id, prev_run_id, started_at, finished_at,
    duration_ms, tool_name, tool_version, vcs_origin, vcs_branch, vcs_commit,
    scanners, scope_hash, counts, delta, unreadable, problem, document, synced_at
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
    $18, $19, $20, now()
)
ON CONFLICT (repo_id, client_run_id) DO UPDATE SET
    source = EXCLUDED.source,
    prev_run_id = EXCLUDED.prev_run_id,
    started_at = EXCLUDED.started_at,
    finished_at = EXCLUDED.finished_at,
    duration_ms = EXCLUDED.duration_ms,
    tool_name = EXCLUDED.tool_name,
    tool_version = EXCLUDED.tool_version,
    vcs_origin = EXCLUDED.vcs_origin,
    vcs_branch = EXCLUDED.vcs_branch,
    vcs_commit = EXCLUDED.vcs_commit,
    scanners = EXCLUDED.scanners,
    scope_hash = EXCLUDED.scope_hash,
    counts = EXCLUDED.counts,
    delta = EXCLUDED.delta,
    unreadable = EXCLUDED.unreadable,
    problem = EXCLUDED.problem,
    document = EXCLUDED.document,
    synced_at = now()
RETURNING id, org_id, repo_id, source, client_run_id, prev_run_id, started_at, finished_at,
          duration_ms, tool_name, tool_version, vcs_origin, vcs_branch, vcs_commit,
          scanners, scope_hash, counts, delta, unreadable, problem, document, synced_at;

-- name: GetRunByID :one
SELECT id, org_id, repo_id, source, client_run_id, prev_run_id, started_at, finished_at,
       duration_ms, tool_name, tool_version, vcs_origin, vcs_branch, vcs_commit,
       scanners, scope_hash, counts, delta, unreadable, problem, document, synced_at
FROM runs
WHERE org_id = $1 AND repo_id = $2 AND id = $3;

-- name: ListRunsByRepo :many
SELECT id, org_id, repo_id, source, client_run_id, prev_run_id, started_at, finished_at,
       duration_ms, tool_name, tool_version, vcs_origin, vcs_branch, vcs_commit,
       scanners, scope_hash, counts, delta, unreadable, problem, document, synced_at
FROM runs
WHERE org_id = $1 AND repo_id = $2
ORDER BY finished_at DESC;

-- name: DeleteFindingsByRun :exec
DELETE FROM findings
WHERE org_id = $1 AND run_id = $2;

-- name: InsertFinding :exec
INSERT INTO findings (
    org_id, repo_id, run_id, fingerprint, scanner, scanners, rule_id, aliases,
    category, severity, title, message, location_path, location_start_line,
    location_end_line, location_snippet, package_name, package_version,
    package_ecosystem, package_purl, fixed_in, refs, status
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
    $18, $19, $20, $21, $22, $23
);

-- name: ListFindingsByRunFiltered :many
SELECT
    f.id, f.org_id, f.repo_id, f.run_id, f.fingerprint, f.scanner, f.scanners, f.rule_id, f.aliases,
    f.category, f.severity, f.title, f.message, f.location_path, f.location_start_line,
    f.location_end_line, f.location_snippet, f.package_name, f.package_version,
    f.package_ecosystem, f.package_purl, f.fixed_in, f.refs, f.status,
    fs.first_seen_at
FROM findings f
LEFT JOIN finding_states fs
    ON fs.org_id = f.org_id AND fs.repo_id = f.repo_id AND fs.fingerprint = f.fingerprint
WHERE f.org_id = sqlc.arg(org_id) AND f.run_id = sqlc.arg(run_id)
  AND (sqlc.arg(severity) = '' OR f.severity = sqlc.arg(severity))
  AND (sqlc.arg(category) = '' OR f.category = sqlc.arg(category))
  AND (sqlc.arg(status) = '' OR f.status = sqlc.arg(status))
  AND (sqlc.arg(search) = '' OR (
    f.title ILIKE '%' || sqlc.arg(search) || '%'
    OR f.message ILIKE '%' || sqlc.arg(search) || '%'
    OR f.rule_id ILIKE '%' || sqlc.arg(search) || '%'
    OR f.location_path ILIKE '%' || sqlc.arg(search) || '%'
  ))
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 5
        WHEN 'high' THEN 4
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 2
        WHEN 'info' THEN 1
        ELSE 0
    END DESC,
    f.fingerprint
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: CountFindingsByRunFiltered :one
SELECT COUNT(*)::bigint AS count
FROM findings f
WHERE f.org_id = sqlc.arg(org_id) AND f.run_id = sqlc.arg(run_id)
  AND (sqlc.arg(severity) = '' OR f.severity = sqlc.arg(severity))
  AND (sqlc.arg(category) = '' OR f.category = sqlc.arg(category))
  AND (sqlc.arg(status) = '' OR f.status = sqlc.arg(status))
  AND (sqlc.arg(search) = '' OR (
    f.title ILIKE '%' || sqlc.arg(search) || '%'
    OR f.message ILIKE '%' || sqlc.arg(search) || '%'
    OR f.rule_id ILIKE '%' || sqlc.arg(search) || '%'
    OR f.location_path ILIKE '%' || sqlc.arg(search) || '%'
  ));

-- name: DeleteFindingStatesByRepo :exec
DELETE FROM finding_states
WHERE org_id = $1 AND repo_id = $2;

-- name: InsertFindingState :exec
INSERT INTO finding_states (
    org_id, repo_id, fingerprint, status, severity, category, title, scanners,
    first_seen_at, last_seen_at, first_run, last_run, fixed_at, fixed_run,
    occurrences, regressions
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
);

-- name: ListFindingStatesByRepo :many
SELECT org_id, repo_id, fingerprint, status, severity, category, title, scanners,
       first_seen_at, last_seen_at, first_run, last_run, fixed_at, fixed_run,
       occurrences, regressions
FROM finding_states
WHERE org_id = $1 AND repo_id = $2
ORDER BY last_seen_at DESC;

-- name: CountOpenFindingsByRepo :one
SELECT COUNT(*)::bigint AS count
FROM finding_states
WHERE org_id = $1 AND repo_id = $2 AND status IN ('new', 'open', 'regressed');

-- name: CountOpenFindingsBySeverityByRepo :many
SELECT severity, COUNT(*)::bigint AS count
FROM finding_states
WHERE org_id = $1 AND repo_id = $2 AND status IN ('new', 'open', 'regressed')
GROUP BY severity;

-- name: CountRunsByRepo :one
SELECT COUNT(*)::bigint AS count
FROM runs
WHERE org_id = $1 AND repo_id = $2;
