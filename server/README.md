# Pindrop product API

Go HTTP API for the commercial Pindrop product. Lives in its own Go module so
the CLI binary stays lean — see [`go.work`](../go.work) at the repo root.

Auth is delegated to **Supabase**: this server verifies JWT access tokens issued
by Supabase Auth. OAuth login happens in [`app/`](../app/).

Scan history is stored in **Postgres** (Supabase's free tier works). The server
connects via `DATABASE_URL` using `pgx` — not PostgREST — so the database can
move to any Postgres host later.

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/healthz` | No | Liveness check |
| `GET` | `/api/v1/me` | Bearer JWT | Returns verified user id and email |
| `PUT` | `/api/v1/sync/repos/{clientRepoId}` | Bearer JWT | Upsert CLI repo link + canonical repo |
| `PUT` | `/api/v1/sync/repos/{clientRepoId}/runs/{clientRunId}` | Bearer JWT | Upsert one run and its findings |
| `PUT` | `/api/v1/sync/repos/{clientRepoId}/states` | Bearer JWT | Replace lifecycle index snapshot |
| `GET` | `/api/v1/repos` | Bearer JWT | List synced repos (`?source=cli` optional) |
| `GET` | `/api/v1/repos/{repoId}` | Bearer JWT | One repo with connection links |
| `GET` | `/api/v1/repos/{repoId}/runs` | Bearer JWT | Runs, newest first |
| `GET` | `/api/v1/repos/{repoId}/runs/{runId}` | Bearer JWT | One run |
| `GET` | `/api/v1/repos/{repoId}/runs/{runId}/findings` | Bearer JWT | Findings for a run |
| `GET` | `/api/v1/repos/{repoId}/states` | Bearer JWT | Lifecycle index |

## Environment

| Variable | Required | Default | Description |
|---|---|---|---|
| `SUPABASE_PROJECT_URL` | Yes | — | Supabase project URL, e.g. `https://abc.supabase.co` |
| `DATABASE_URL` | Yes | — | Postgres connection string |
| `PORT` | No | `8080` | Listen port |
| `CORS_ORIGIN` | No | `http://localhost:5174` | Allowed browser origin for CORS |

## Development

Copy the example env file and fill in your Supabase project URL:

```bash
cd server
cp .env.example .env
# edit .env — SUPABASE_PROJECT_URL for auth; DATABASE_URL for scan history
```

### Local Postgres (Docker)

If you run Postgres in Docker (e.g. on port `54320` with admin user `user`), create a
dedicated app database once:

```bash
PGPASSWORD=password psql -h localhost -p 54320 -U user -d postgres <<'SQL'
CREATE ROLE pindrop LOGIN PASSWORD 'pindrop_local_dev';
CREATE DATABASE pindrop_dev OWNER pindrop;
GRANT ALL PRIVILEGES ON DATABASE pindrop_dev TO pindrop;
SQL

PGPASSWORD=password psql -h localhost -p 54320 -U user -d pindrop_dev -c \
  "GRANT ALL ON SCHEMA public TO pindrop;"
```

Then set in `server/.env`:

```
DATABASE_URL=postgresql://pindrop:pindrop_local_dev@localhost:54320/pindrop_dev?sslmode=disable
```

Migrations run automatically on `make server-dev`.

From the repo root (recommended — clears a stale GOROOT that causes
`compile: version "goX" does not match go tool version "goY"`):

```bash
make server-dev
```

Or directly, unsetting GOROOT the way the Makefile does:

```bash
cd server
env -u GOROOT go run ./cmd/server
```

Config is loaded via [`caarlos0/env`](https://github.com/caarlos0/env) from the
process environment, with [`godotenv`](https://github.com/joho/godotenv) loading
`server/.env` automatically when present.

If you use mise, ensure `go = "1.26.5"` in [`mise.toml`](../mise.toml) matches
[`go.mod`](go.mod)'s `toolchain` directive.

Verify:

```bash
curl http://127.0.0.1:8080/api/v1/healthz

# Copy access_token from the browser session (Supabase) after signing in via app/.
curl -H "Authorization: Bearer <access_token>" http://127.0.0.1:8080/api/v1/me
curl -H "Authorization: Bearer <access_token>" http://127.0.0.1:8080/api/v1/repos
```

## SQL codegen

After editing `internal/syncstore/postgres/query.sql` or migrations:

```bash
make server-sqlc
```

## Tests

```bash
make server-test
# or: cd server && env -u GOROOT go test ./...
```

Store integration tests use testcontainers and require Docker.
