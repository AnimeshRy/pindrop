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

## Deploying to Cloud Run

The API is a long-running process with a pgx pool and startup migrations, so it
runs as a container, not a serverless function. `Dockerfile` is the deploy
artifact and Cloud Build builds it from source, so no local Docker is needed.

### Console setup (no gcloud required)

**1. Store the database URL as a secret.** Secret Manager → *Create secret*,
name `pindrop-database-url`, value the Supabase **transaction pooler** string
with a pool cap appended:

```
postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres?sslmode=require&pool_max_conns=5
```

**2. Create the service.** Cloud Run → *Create service* → *Continuously deploy
from a repository* → connect the GitHub repo, then set:

| Field | Value |
|---|---|
| Branch | `^main$` |
| Build type | Dockerfile |
| Dockerfile path | `/server/Dockerfile` |

The UI shows no build-context field, but it derives one from the Dockerfile
path: the generated trigger's build step is `docker build ... server -f
server/Dockerfile`, so the context is `server/`. That is why `Dockerfile` uses
plain `COPY go.mod go.sum ./` and `server/.dockerignore` sits beside it. The
context is invisible in the UI and only appears in the trigger's build step, so
check there before changing any `COPY` path.

**3. Service settings.**

| Setting | Value |
|---|---|
| Authentication | Allow unauthenticated invocations |
| Min instances | 0 |
| Max instances | 3 |
| Memory / CPU | 512 MiB / 1 |
| Request timeout | 60s |

"Allow unauthenticated" is correct and not a hole: every route except
`/api/v1/healthz` requires a Supabase JWT, verified by `internal/authmw`. IAM
auth would instead block the CLI and browser, which hold user tokens, not
Google credentials.

**4. Environment variables.**

| Variable | Value |
|---|---|
| `SUPABASE_PROJECT_URL` | `https://<ref>.supabase.co` |
| `CORS_ORIGIN` | the deployed frontend origin, e.g. `https://pindrop.nimesh.ink` |
| `DATABASE_URL` | *reference the secret* `pindrop-database-url`, exposed as an env var |

Do **not** set `PORT` — Cloud Run injects it, and a hardcoded value makes the
container fail its health check.

### Things that will bite you

**Use Supabase's pooler, never the direct connection.** Cloud Run egress is IPv4
and Supabase's direct Postgres endpoint is IPv6-only, so a direct URL fails to
connect at all. The pooler (`...pooler.supabase.com`) is IPv4.

**The pooler is why `Open` forces `QueryExecModeDescribeExec`.** Supabase's
transaction pooler is PgBouncer, which cannot carry pgx's default server-side
prepared statements across a pooled connection. Reverting that line breaks every
query in production while leaving local development against a direct Postgres
green. Do not "simplify" it further to `Exec` or `SimpleProtocol` either: both
drop the Describe round trip, and without the parameter OIDs it returns, pgx
encodes the jsonb columns as bytea and every repo sync fails with `invalid input
syntax for type json`.

**Cap the pool in the connection string** — `pool_max_conns=5`. The default is
one connection per CPU multiplied by every Cloud Run instance, which exhausts
the pooler's client limit long before the service is under real load.

**`DATABASE_URL` holds a password**, so it belongs in Secret Manager, not in a
plain environment variable where it is readable from the service description.

### If the build fails at FETCHSOURCE

```
error fetching DeveloperConnect credentials: ... Permission
'developerconnect.gitRepositoryLinks.fetchReadToken' denied
```

This is IAM, not the build: Cloud Build cannot read the GitHub link, so it never
reaches the Dockerfile. Grant the build's service account (the Compute Engine
default, `<project-number>-compute@developer.gserviceaccount.com`, unless the
trigger names another) the **Developer Connect Read Token Accessor** role
(`roles/developerconnect.readTokenAccessor`) in IAM.

Note the Developer Connect connection is created in the *trigger's* region,
which the console may place somewhere other than the service's region — the
error message carries the connection's real location, and it is the one that
matters when granting at connection scope rather than project scope.

### Custom domain

The generated `run.app` URL is stable across revisions, but it encodes the
project and region, and the CLI bakes its API URL into released binaries at link
time (`internal/cliauth`, `-ldflags -X`). Shipped binaries cannot be corrected
remotely, so map a domain before setting that default and never point it at
`run.app`.

Cloud Run → *Manage custom domains* → add e.g. `api.pindrop.nimesh.ink`, then
create the CNAME it gives you. If the domain is on Cloudflare, that record must
be **DNS-only (grey cloud)**: Cloud Run routes by `Host` header, and a proxied
request arrives with the custom hostname, which an unmapped service answers with
a bare 404 that looks like the app is broken.

### After the service is up

1. Set the frontend's `VITE_API_BASE_URL` to the API origin and redeploy it.
2. Set `CORS_ORIGIN` to the frontend origin — the two are mutually referential,
   so one of them is always a second pass.
3. Point the CLI at it via `PINDROP_API_URL`, and only once the domain is final,
   as the `-ldflags` default.
