import { QuanticNetworkApp } from "@/components/quantic-network-app";

export default function Home() {
  return (
    <>
      <QuanticNetworkApp />
      <a className="qn-vault-fab" href="/vault" title="Sauvegarder ou restaurer mon identité Quantic">
        Identity Vault
      </a>
    </>
  );
}
