export function QuanticGlobalNav() {
  return (
    <header className="qn-global-nav" aria-label="Navigation Quantic">
      <a className="qn-global-brand" href="/">
        <span className="qn-global-mark" aria-hidden="true" />
        <span>QUANTIC</span>
      </a>
      <nav className="qn-global-links">
        <a href="/vision/">Vision</a>
        <a className="active" href="/mail/" aria-current="page">Mail</a>
        <a href="/network/">Network</a>
        <a href="/products/">Produits</a>
        <a className="centre" href="/quantic/">Centre</a>
      </nav>
    </header>
  );
}
