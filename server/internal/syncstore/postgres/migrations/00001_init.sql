-- +goose Up
-- SaaS scan history: tenancy, canonical repos, connection links, runs, findings.

CREATE TABLE users (
    id         UUID PRIMARY KEY,
    email      TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE orgs (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE org_members (
    org_id  UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    TEXT NOT NULL DEFAULT 'owner',
    PRIMARY KEY (org_id, user_id)
);

CREATE INDEX idx_org_members_user_id ON org_members(user_id);

-- Canonical repository: one row per real-world repo per org.
CREATE TABLE repos (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    origin          TEXT NOT NULL DEFAULT '',
    last_run_id     TEXT NOT NULL DEFAULT '',
    first_synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, id)
);

CREATE INDEX idx_repos_org_id ON repos(org_id);
CREATE INDEX idx_repos_origin ON repos(org_id, origin) WHERE origin <> '';

-- One row per way a canonical repo is connected (CLI sync, GitHub App, ...).
CREATE TABLE repo_links (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repo_id         UUID NOT NULL,
    source          TEXT NOT NULL,
    external_id     TEXT NOT NULL,
    path            TEXT NOT NULL DEFAULT '',
    former_paths    JSONB NOT NULL DEFAULT '[]',
    metadata        JSONB NOT NULL DEFAULT '{}',
    first_synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, source, external_id),
    FOREIGN KEY (org_id, repo_id) REFERENCES repos (org_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_repo_links_repo_id ON repo_links(repo_id);

CREATE TABLE runs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repo_id       UUID NOT NULL,
    source        TEXT NOT NULL DEFAULT 'cli',
    client_run_id TEXT NOT NULL,
    prev_run_id   TEXT NOT NULL DEFAULT '',
    started_at    TIMESTAMPTZ NOT NULL,
    finished_at   TIMESTAMPTZ NOT NULL,
    duration_ms   BIGINT NOT NULL DEFAULT 0,
    tool_name     TEXT NOT NULL DEFAULT '',
    tool_version  TEXT NOT NULL DEFAULT '',
    vcs_origin    TEXT NOT NULL DEFAULT '',
    vcs_branch    TEXT NOT NULL DEFAULT '',
    vcs_commit    TEXT NOT NULL DEFAULT '',
    scanners      JSONB NOT NULL DEFAULT '[]',
    scope_hash    TEXT NOT NULL DEFAULT '',
    counts        JSONB NOT NULL DEFAULT '{}',
    delta         JSONB NOT NULL DEFAULT '{}',
    unreadable    BOOLEAN NOT NULL DEFAULT false,
    problem       TEXT NOT NULL DEFAULT '',
    document      JSONB NOT NULL DEFAULT '{}',
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repo_id, client_run_id),
    UNIQUE (repo_id, id),
    FOREIGN KEY (org_id, repo_id) REFERENCES repos (org_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_runs_org_id ON runs(org_id);
CREATE INDEX idx_runs_repo_id ON runs(repo_id);

CREATE TABLE findings (
    id                  BIGSERIAL PRIMARY KEY,
    org_id              UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repo_id             UUID NOT NULL,
    run_id              UUID NOT NULL,
    fingerprint         TEXT NOT NULL,
    scanner             TEXT NOT NULL DEFAULT '',
    scanners            JSONB NOT NULL DEFAULT '[]',
    rule_id             TEXT NOT NULL DEFAULT '',
    aliases             JSONB NOT NULL DEFAULT '[]',
    category            TEXT NOT NULL DEFAULT '',
    severity            TEXT NOT NULL DEFAULT '',
    title               TEXT NOT NULL DEFAULT '',
    message             TEXT NOT NULL DEFAULT '',
    location_path       TEXT NOT NULL DEFAULT '',
    location_start_line INTEGER NOT NULL DEFAULT 0,
    location_end_line   INTEGER NOT NULL DEFAULT 0,
    location_snippet    TEXT NOT NULL DEFAULT '',
    package_name        TEXT NOT NULL DEFAULT '',
    package_version     TEXT NOT NULL DEFAULT '',
    package_ecosystem   TEXT NOT NULL DEFAULT '',
    package_purl        TEXT NOT NULL DEFAULT '',
    fixed_in            TEXT NOT NULL DEFAULT '',
    refs                JSONB NOT NULL DEFAULT '[]',
    status              TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (org_id, repo_id) REFERENCES repos (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, run_id) REFERENCES runs (repo_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_findings_run_id ON findings(run_id);
CREATE INDEX idx_findings_repo_fingerprint ON findings(repo_id, fingerprint);

CREATE TABLE finding_states (
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repo_id       UUID NOT NULL,
    fingerprint   TEXT NOT NULL,
    status        TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT '',
    category      TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL DEFAULT '',
    scanners      JSONB NOT NULL DEFAULT '[]',
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL,
    first_run     TEXT NOT NULL DEFAULT '',
    last_run      TEXT NOT NULL DEFAULT '',
    fixed_at      TIMESTAMPTZ,
    fixed_run     TEXT NOT NULL DEFAULT '',
    occurrences   INTEGER NOT NULL DEFAULT 0,
    regressions   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (repo_id, fingerprint),
    FOREIGN KEY (org_id, repo_id) REFERENCES repos (org_id, id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE IF EXISTS finding_states;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS repo_links;
DROP TABLE IF EXISTS repos;
DROP TABLE IF EXISTS org_members;
DROP TABLE IF EXISTS orgs;
DROP TABLE IF EXISTS users;
