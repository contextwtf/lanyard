import CreateRoot from 'components/CreateRoot'
import FAQ from 'components/FAQ'

export default function CreatePage() {
  return (
    <div className="flex flex-col mb-24">
      <div className="font-bold text-2xl text-center my-10">
        Create an allow list in seconds that works across web3
      </div>

      <CreateRoot />

      <div className="flex gap-3 sm:gap-4 text-base mt-10 items-center">
        <img
          src="/collablogos.png"
          alt="partner logos"
          className="w-[64px] sm:w-[84px]"
        />
        <div>
          An open source project from{' '}
          <PartnerLink href="https://context.app">Context</PartnerLink>,{' '}
          <PartnerLink href="https://zora.co">Zora</PartnerLink>, and{' '}
          <PartnerLink href="https://mint.fun">mint.fun</PartnerLink>
        </div>
      </div>

      <div className="h-px bg-neutral-200 my-10 sm:my-16 w-full" />

      <FAQ />
    </div>
  )
}

const PartnerLink = ({
  href,
  children,
}: {
  href: string
  children: React.ReactNode
}) => (
  <a
    href={href}
    className="font-bold hover:underline"
    target="_blank"
    rel="noopener noreferrer"
  >
    {children}
  </a>
)
