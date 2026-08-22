import { Link, useRouter } from '@tanstack/react-router'
import {
  BookOpen,
  ChevronDown,
  FolderGit2,
  History,
  LayoutGrid,
  ListChecks,
  ListTodo,
  LogOut,
  Plug,
  Settings,
  Users,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

import { PindropLogo } from '@/components/pindrop-logo'
import { useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'

/** Live nav items, in the order they should appear under "Workspace". */
const WORKSPACE_ITEMS = [
  { label: 'Overview', to: '/dashboard' as const, icon: LayoutGrid },
  { label: 'Repositories', to: '/repos' as const, icon: FolderGit2 },
]

/**
 * Nav items with no page behind them yet. Shown so the product's shape is
 * visible, but never linked — a dead link is worse than an absent one.
 */
const WORKSPACE_SOON = [
  { label: 'Findings', icon: ListChecks },
  { label: 'Scan runs', icon: History },
  { label: 'Triage', icon: ListTodo },
  { label: 'Rules', icon: BookOpen },
]

const SETUP_SOON = [
  { label: 'Integrations', icon: Plug },
  { label: 'Members', icon: Users },
  { label: 'Settings', icon: Settings },
]

/** Persistent left navigation for authenticated pages. */
export function AppSidebar() {
  return (
    <aside
      className="flex h-full w-64 shrink-0 flex-col border-r"
      style={{ borderColor: 'var(--border)' }}
    >
      <div
        className="flex h-14 items-center border-b px-4"
        style={{ borderColor: 'var(--border)' }}
      >
        <PindropLogo to="/dashboard" />
      </div>

      <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-4">
        <div>
          <SectionLabel>Workspace</SectionLabel>
          <ul className="mt-1 space-y-0.5">
            {WORKSPACE_ITEMS.map((item) => (
              <li key={item.label}>
                <NavLink to={item.to} icon={item.icon} label={item.label} />
              </li>
            ))}
            {WORKSPACE_SOON.map((item) => (
              <li key={item.label}>
                <SoonRow icon={item.icon} label={item.label} />
              </li>
            ))}
          </ul>
        </div>

        <div>
          <SectionLabel>Setup</SectionLabel>
          <ul className="mt-1 space-y-0.5">
            {SETUP_SOON.map((item) => (
              <li key={item.label}>
                <SoonRow icon={item.icon} label={item.label} />
              </li>
            ))}
          </ul>
        </div>
      </nav>

      <div className="space-y-3 border-t p-3" style={{ borderColor: 'var(--border)' }}>
        <div
          className="rounded-lg border p-3 text-xs"
          style={{ borderColor: 'var(--border)', backgroundColor: 'var(--muted)' }}
        >
          <p className="font-medium">Sync from CLI</p>
          <code className="mt-1 block truncate text-[var(--muted-foreground)]">
            pindrop sync
          </code>
        </div>

        <UserMenu />
      </div>
    </aside>
  )
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p
      className="px-2 text-xs font-medium tracking-wide uppercase"
      style={{ color: 'var(--muted-foreground)' }}
    >
      {children}
    </p>
  )
}

function NavLink({
  to,
  icon: Icon,
  label,
}: {
  to: '/dashboard' | '/repos'
  icon: typeof LayoutGrid
  label: string
}) {
  return (
    <Link
      to={to}
      className="flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors hover:bg-[var(--muted)]"
      activeProps={{
        className: 'bg-[var(--muted)] font-medium text-[var(--foreground)]',
        'aria-current': 'page',
      }}
      inactiveProps={{ className: 'text-[var(--muted-foreground)]' }}
    >
      <Icon className="size-4 shrink-0" aria-hidden />
      {label}
    </Link>
  )
}

function SoonRow({ icon: Icon, label }: { icon: typeof LayoutGrid; label: string }) {
  return (
    <div
      className="flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm"
      style={{ color: 'var(--muted-foreground)' }}
      title={`${label} is coming soon`}
    >
      <Icon className="size-4 shrink-0 opacity-60" aria-hidden />
      <span className="opacity-60">{label}</span>
      <span
        className="ml-auto rounded-full px-1.5 py-0.5 text-[10px] font-medium uppercase"
        style={{ backgroundColor: 'var(--muted)' }}
      >
        Soon
      </span>
    </div>
  )
}

/** Account row with a click-to-open sign-out menu. */
function UserMenu() {
  const auth = useAuth()
  const router = useRouter()
  const [open, setOpen] = useState(false)
  const [signingOut, setSigningOut] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) {
      return
    }
    function onPointerDown(event: PointerEvent) {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('pointerdown', onPointerDown)
    return () => document.removeEventListener('pointerdown', onPointerDown)
  }, [open])

  const user = auth.user
  if (!user) {
    return null
  }

  const displayName =
    (user.user_metadata.full_name as string | undefined) ??
    (user.user_metadata.name as string | undefined) ??
    user.email ??
    'User'
  const avatarUrl =
    (user.user_metadata.avatar_url as string | undefined) ??
    (user.user_metadata.picture as string | undefined)

  async function handleSignOut() {
    setSigningOut(true)
    try {
      await auth.signOut()
      await router.navigate({ to: '/login' })
    } finally {
      setSigningOut(false)
    }
  }

  return (
    <div className="relative" ref={ref}>
      <div
        className="flex items-center gap-1 rounded-lg border px-1 py-1"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
      >
        <div className="flex min-w-0 flex-1 items-center gap-2.5 px-1.5 py-0.5">
          {avatarUrl ? (
            <img
              src={avatarUrl}
              alt=""
              className="size-8 shrink-0 rounded-full object-cover"
            />
          ) : (
            <div
              className="flex size-8 shrink-0 items-center justify-center rounded-full text-sm font-medium"
              style={{ backgroundColor: 'var(--muted)' }}
            >
              {displayName.charAt(0).toUpperCase()}
            </div>
          )}
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">{displayName}</p>
            {user.email ? (
              <p
                className="truncate text-xs"
                style={{ color: 'var(--muted-foreground)' }}
              >
                {user.email}
              </p>
            ) : null}
          </div>
        </div>

        <button
          type="button"
          aria-expanded={open}
          aria-haspopup="menu"
          aria-label="Account menu"
          onClick={() => setOpen((v) => !v)}
          className={cn(
            'inline-flex size-8 shrink-0 items-center justify-center rounded-md transition-colors hover:bg-[var(--muted)]',
            open && 'bg-[var(--muted)]',
          )}
        >
          <ChevronDown
            className={cn('size-4 transition-transform', open && 'rotate-180')}
            aria-hidden
          />
        </button>
      </div>

      {open ? (
        <div
          role="menu"
          className="absolute right-0 bottom-full left-0 mb-2 overflow-hidden rounded-lg border shadow-sm"
          style={{ borderColor: 'var(--border)', backgroundColor: 'var(--card)' }}
        >
          <button
            type="button"
            role="menuitem"
            disabled={signingOut}
            onClick={() => void handleSignOut()}
            className="flex w-full items-center gap-2 border-t px-3 py-2.5 text-left text-sm transition-colors hover:bg-[var(--muted)] disabled:cursor-not-allowed disabled:opacity-60"
            style={{ borderColor: 'var(--border)' }}
          >
            <LogOut className="size-4" aria-hidden />
            {signingOut ? 'Signing out…' : 'Sign out'}
          </button>
        </div>
      ) : null}
    </div>
  )
}
