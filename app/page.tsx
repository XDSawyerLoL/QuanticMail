import Link from "next/link";
import { QuanticManifestGate } from "@/components/quantic-manifest-gate";
import { QuanticNetworkV11App } from "@/components/quantic-network-v11-app";

export default function Home() {
  return (
    <>
      <QuanticManifestGate>
        <QuanticNetworkV11App />
      </QuanticManifestGate>
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
