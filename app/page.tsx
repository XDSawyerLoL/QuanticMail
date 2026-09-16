import Link from "next/link";
import { QuanticNetworkApp } from "@/components/quantic-network-app";

export default function Home() {
  return (
    <>
      <QuanticNetworkApp />
      <Link
        className="qn-vault-fab"
        href="/network"
        title="Configurer les relais Quantic Network"
        style={{ bottom: 62 }}
      >
        Réseau
      </Link>
      <Link className="qn-vault-fab" href="/vault" title="Sauvegarder ou restaurer mon identité Quantic">
        Identity Vault
      </Link>
    </>
  );
}
