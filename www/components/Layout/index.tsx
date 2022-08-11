import SiteNav from 'components/SiteNav'
import MetaTags from 'components/MetaTags'
import { ReactNode } from 'react'
import { siteDescription } from 'utils/constants'

type Props = {
  children: ReactNode
}

export default function Layout({ children }: Props) {
  return (
    <div className="flex flex-col items-center overflow-x-hidden">
      <MetaTags description={siteDescription} />

      <div className="w-full max-w-screen-lg px-3 md:px-8 pb-8">
        <SiteNav />
        <main>{children}</main>
      </div>
    </div>
  )
}
