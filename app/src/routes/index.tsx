import { createFileRoute } from '@tanstack/react-router'

import { HomePage } from '@/components/home/home-page'

export const Route = createFileRoute('/')({
  component: IndexPage,
})

function IndexPage() {
  const { auth } = Route.useRouteContext()

  return <HomePage signedIn={Boolean(auth.user)} />
}
