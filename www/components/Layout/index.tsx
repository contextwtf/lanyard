import { ReactNode } from 'react'
import SiteNav from 'components/SiteNav'
import MetaTags from 'components/MetaTags'
import { siteDescription } from 'utils/constants'
import Head from './Head'

type Props = {
  children: ReactNode
}

export default function Layout({ children }: Props) {
  return (
    <div className="flex flex-col items-center overflow-x-hidden pb-20">
      <MetaTags
        description={siteDescription}
        // og:image spec requires full url, can't use path for image
        imageUrl="https://lanyard.org/meta-image.png?v=2"
      />
      <Head />

      <div className="w-full max-w-screen-lg px-3 sm:px-8 pb-8">
        <SiteNav />
        <main>{children}</main>
      </div>
    </div>
  )
}
