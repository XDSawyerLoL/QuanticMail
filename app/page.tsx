import Link from "next/link";
import { QuanticNetworkApp } from "@/components/quantic-network-app";

export default function Home() {
  return (
    <>
      <QuanticNetworkApp />
      <div className="qn-fab-stack">
        <Link className="qn-vault-fab" href="/devices" title="Gérer les appareils Quantic">
          Appareils
        </Link>
        <Link className="qn-vault-fab" href="/vault" title="Sauvegarder ou restaurer mon identité Quantic">
          Identity Vault
        </Link>
      </div>
    </>
  );
}
