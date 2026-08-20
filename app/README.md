# Pindrop product app

Browser UI for the commercial Pindrop product. This is **separate** from
[`web/`](../web/), which is the CLI's embedded local dashboard served by
`pindrop serve`.

## Stack

- Vite + React + TypeScript
- TanStack Router
- Tailwind CSS v4
- Supabase Auth (GitHub + Google OAuth)

## Setup

```bash
cd app
cp .env.example .env.local
# Fill in VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY from the Supabase dashboard.
pnpm install
```

In Supabase → Authentication → URL Configuration, add your local and production
redirect URLs (e.g. `http://localhost:5174/dashboard`).

## Development

Run the API server in one terminal:

```bash
export SUPABASE_PROJECT_URL=https://your-project-ref.supabase.co
make server-dev
```

Run the frontend in another:

```bash
make app-dev
```

Open [http://localhost:5174](http://localhost:5174). API requests to `/api/*` are
proxied to `http://127.0.0.1:8080`.

## Scripts

| Command          | Description                        |
| ---------------- | ---------------------------------- |
| `pnpm dev`       | Start Vite dev server on port 5174 |
| `pnpm build`     | Production build to `dist/`        |
| `pnpm typecheck` | TypeScript check                   |
| `pnpm lint`      | ESLint                             |

## Deployment

`pnpm build` produces a static SPA in `dist/`. Deploy to Vercel, Netlify, or any
static host. Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` as build-time
environment variables.

Point `CORS_ORIGIN` on the API server at your deployed frontend origin.
