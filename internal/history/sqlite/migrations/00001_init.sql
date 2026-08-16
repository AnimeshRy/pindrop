-- +goose Up
-- Scan history schema: repos, runs, per-run findings, and the lifecycle index.

CREATE TABLE repos (
    id            TEXT PRIMARY KEY NOT NULL,
    name          TEXT NOT NULL,
    path          TEXT NOT NULL,
    former_paths  TEXT NOT NULL DEFAULT '[]',
    origin        TEXT NOT NULL DEFAULT '',
    first_run_at  TEXT NOT NULL,
    last_run_at   TEXT NOT NULL,
    last_run_id   TEXT NOT NULL
);

CREATE TABLE runs (
    id             TEXT PRIMARY KEY NOT NULL,
    repo_id        TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    prev_run_id    TEXT NOT NULL DEFAULT '',
    started_at     TEXT NOT NULL,
    finished_at    TEXT NOT NULL,
    duration_ms    INTEGER NOT NULL DEFAULT 0,
    tool_name      TEXT NOT NULL DEFAULT '',
    tool_version   TEXT NOT NULL DEFAULT '',
    vcs_origin     TEXT NOT NULL DEFAULT '',
    vcs_branch     TEXT NOT NULL DEFAULT '',
    vcs_commit     TEXT NOT NULL DEFAULT '',
    scanners       TEXT NOT NULL DEFAULT '[]',
    scope_hash     TEXT NOT NULL DEFAULT '',
    counts         TEXT NOT NULL DEFAULT '{}',
    delta          TEXT NOT NULL DEFAULT '{}',
    unreadable     INTEGER NOT NULL DEFAULT 0,
    problem        TEXT NOT NULL DEFAULT '',
    document       TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_runs_repo_id ON runs(repo_id);
CREATE INDEX idx_runs_repo_id_id ON runs(repo_id, id);

CREATE TABLE findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    repo_id       TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    fingerprint   TEXT NOT NULL,
    scanner       TEXT NOT NULL DEFAULT '',
    scanners      TEXT NOT NULL DEFAULT '[]',
    rule_id       TEXT NOT NULL DEFAULT '',
    aliases       TEXT NOT NULL DEFAULT '[]',
    category      TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL DEFAULT '',
    message       TEXT NOT NULL DEFAULT '',
    location_path TEXT NOT NULL DEFAULT '',
    location_start_line INTEGER NOT NULL DEFAULT 0,
    location_end_line   INTEGER NOT NULL DEFAULT 0,
    location_snippet    TEXT NOT NULL DEFAULT '',
    package_name      TEXT NOT NULL DEFAULT '',
    package_version   TEXT NOT NULL DEFAULT '',
    package_ecosystem TEXT NOT NULL DEFAULT '',
    package_purl      TEXT NOT NULL DEFAULT '',
    fixed_in          TEXT NOT NULL DEFAULT '',
    refs              TEXT NOT NULL DEFAULT '[]',
    status            TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_findings_run_id ON findings(run_id);
CREATE INDEX idx_findings_repo_fingerprint ON findings(repo_id, fingerprint);

CREATE TABLE finding_states (
    repo_id       TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    fingerprint   TEXT NOT NULL,
    status        TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT '',
    category      TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL DEFAULT '',
    scanners      TEXT NOT NULL DEFAULT '[]',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    first_run     TEXT NOT NULL,
    last_run      TEXT NOT NULL,
    fixed_at      TEXT NOT NULL DEFAULT '',
    fixed_run     TEXT NOT NULL DEFAULT '',
    occurrences   INTEGER NOT NULL DEFAULT 0,
    regressions   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (repo_id, fingerprint)
);

-- +goose Down
DROP TABLE IF EXISTS finding_states;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS repos;
