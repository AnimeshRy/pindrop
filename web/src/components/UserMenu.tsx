import { useAuth } from '@/lib/auth-context'

export function UserMenu() {
  const { loading, user, signOut } = useAuth()

  if (loading) {
    return (
      <span className="text-sm" style={{ color: 'var(--muted-foreground)' }}>
        …
      </span>
    )
  }

  if (!user) {
    return null
  }

  const initial = user.name.trim().charAt(0).toUpperCase() || '?'

  return (
    <div className="flex items-center gap-3 text-sm">
      {user.avatarUrl ? (
        <img
          src={user.avatarUrl}
          alt=""
          className="size-8 rounded-full"
          referrerPolicy="no-referrer"
        />
      ) : (
        <span
          className="flex size-8 items-center justify-center rounded-full font-medium"
          style={{ background: 'var(--muted)' }}
          aria-hidden
        >
          {initial}
        </span>
      )}
      <span className="max-w-[12rem] truncate font-medium">{user.name}</span>
      <button
        type="button"
        className="underline"
        style={{ color: 'var(--muted-foreground)' }}
        onClick={() => void signOut()}
      >
        Sign out
      </button>
    </div>
  )
}
