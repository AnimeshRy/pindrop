import { createFileRoute, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/')({
  beforeLoad: ({ context }) => {
    if (context.auth.loading) {
      return
    }
    if (context.auth.user) {
      throw redirect({ to: '/dashboard' })
    }
    throw redirect({ to: '/login' })
  },
})
