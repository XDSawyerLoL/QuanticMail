import Link from "next/link";

const PORTAL_ORIGIN="https://mediumorchid-badger-314305.hostingersite.com";

export function QuanticGlobalNav() {
  return (
    <header className="qn-global-nav" aria-label="Navigation Quantic">
      <Link className="qn-global-brand" href={PORTAL_ORIGIN}>
        <span className="qn-global-mark" aria-hidden="true" />
        <span>QUANTIC</span>
      </Link>
      <nav className="qn-global-links">
        <Link href={`${PORTAL_ORIGIN}/vision/`}>Vision</Link>
        <Link className="active" href={`${PORTAL_ORIGIN}/mail/`} aria-current="page">Mail</Link>
        <Link href={`${PORTAL_ORIGIN}/network/`}>Network</Link>
        <Link href={`${PORTAL_ORIGIN}/products/`}>Produits</Link>
        <Link className="centre" href={`${PORTAL_ORIGIN}/quantic/`}>Centre</Link>
      </nav>
    </header>
  );
}
