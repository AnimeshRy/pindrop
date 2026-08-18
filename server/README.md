# Pindrop product API

Go HTTP API for the commercial Pindrop product. Lives in its own Go module so
the CLI binary stays lean — see [`go.work`](../go.work) at the repo root.

Auth is delegated to **Supabase**: this server verifies JWT access tokens issued
by Supabase Auth. OAuth login happens in [`app/`](../app/).

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/healthz` | No | Liveness check |
| `GET` | `/api/v1/me` | Bearer JWT | Returns verified user id and email |

## Environment

| Variable | Required | Default | Description |
|---|---|---|---|
| `SUPABASE_PROJECT_URL` | Yes | — | Supabase project URL, e.g. `https://abc.supabase.co` |
| `PORT` | No | `8080` | Listen port |
| `CORS_ORIGIN` | No | `http://localhost:5174` | Allowed browser origin for CORS |

## Development

Copy the example env file and fill in your Supabase project URL:

```bash
cd server
cp .env.example .env
# edit .env
```

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
```

## Tests

```bash
make server-test
# or: cd server && env -u GOROOT go test ./...
```
