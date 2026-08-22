package cliauth

import (
	"fmt"
	"html"
)

// callbackSuccessHTML is the browser page shown after a successful OAuth callback.
// Styling mirrors app/src/index.css tokens (teal accent, warm neutrals).
const callbackPageCSS = `
:root {
  color-scheme: light;
  --background: oklch(0.985 0.004 95);
  --foreground: oklch(0.2 0.012 260);
  --muted-foreground: oklch(0.48 0.014 260);
  --border: oklch(0.9 0.008 95);
  --card: oklch(1 0 0);
  --accent: oklch(0.55 0.12 175);
  --success: oklch(0.55 0.14 145);
  --danger: oklch(0.55 0.2 25);
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --background: oklch(0.17 0.008 260);
    --foreground: oklch(0.96 0.003 260);
    --muted-foreground: oklch(0.68 0.012 260);
    --border: oklch(0.29 0.01 260);
    --card: oklch(0.2 0.009 260);
    --accent: oklch(0.72 0.11 175);
    --success: oklch(0.72 0.12 145);
    --danger: oklch(0.7 0.16 25);
  }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  background: var(--background);
  color: var(--foreground);
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
  -webkit-font-smoothing: antialiased;
}
.card {
  width: 100%%;
  max-width: 28rem;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 0.75rem;
  padding: 2rem;
  text-align: center;
}
.logo {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
}
.logo-dot {
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 9999px;
  background: var(--accent);
}
.logo-text {
  font-size: 1rem;
  font-weight: 600;
  letter-spacing: -0.02em;
}
.icon {
  font-size: 2rem;
  line-height: 1;
  margin-bottom: 1rem;
}
.icon-success { color: var(--success); }
.icon-error { color: var(--danger); }
h1 {
  font-size: 1.25rem;
  font-weight: 600;
  letter-spacing: -0.02em;
  margin-bottom: 0.5rem;
}
p {
  font-size: 0.875rem;
  color: var(--muted-foreground);
  line-height: 1.5;
}
.error-detail {
  margin-top: 1rem;
  padding: 0.75rem;
  border-radius: 0.5rem;
  border: 1px solid var(--border);
  font-size: 0.8125rem;
  color: var(--danger);
  word-break: break-word;
  text-align: left;
}
`

func callbackSuccessPage() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signed in — Pindrop</title>
<style>%s</style>
</head>
<body>
<main class="card">
  <div class="logo"><span class="logo-dot" aria-hidden="true"></span><span class="logo-text">Pindrop</span></div>
  <div class="icon icon-success" aria-hidden="true">✓</div>
  <h1>You're signed in to Pindrop</h1>
  <p>You can close this tab and return to your terminal.</p>
</main>
<script>setTimeout(function(){ try { window.close(); } catch(e) {} }, 1500);</script>
</body>
</html>`, callbackPageCSS)
}

func callbackErrorPage(errCode, errDesc string) string {
	msg := html.EscapeString(errCode)
	if errDesc != "" {
		if msg != "" {
			msg += " — "
		}
		msg += html.EscapeString(errDesc)
	}
	if msg == "" {
		msg = "Sign-in was cancelled or rejected."
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign-in failed — Pindrop</title>
<style>%s</style>
</head>
<body>
<main class="card">
  <div class="logo"><span class="logo-dot" aria-hidden="true"></span><span class="logo-text">Pindrop</span></div>
  <div class="icon icon-error" aria-hidden="true">✕</div>
  <h1>Sign-in failed</h1>
  <p>Return to your terminal and try again.</p>
  <div class="error-detail" role="alert">%s</div>
</main>
</body>
</html>`, callbackPageCSS, msg)
}
