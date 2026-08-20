import { HomeCta } from '@/components/home/home-cta'
import { HomeFeatures } from '@/components/home/home-features'
import { HomeFooter } from '@/components/home/home-footer'
import { HomeHeader } from '@/components/home/home-header'
import { HomeHero } from '@/components/home/home-hero'
import { HomeScanPreview } from '@/components/home/home-scan-preview'
import { HomeWorkflow } from '@/components/home/home-workflow'

interface HomePageProps {
  signedIn: boolean
}

/** Public marketing homepage composition. */
export function HomePage({ signedIn }: HomePageProps) {
  return (
    <div className="min-h-full">
      <HomeHeader signedIn={signedIn} />
      <main>
        <HomeHero signedIn={signedIn} />
        <HomeScanPreview />
        <HomeFeatures />
        <HomeWorkflow />
        <HomeCta signedIn={signedIn} />
      </main>
      <HomeFooter />
    </div>
  )
}
