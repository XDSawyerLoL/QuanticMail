import Link from "next/link";
import { QuanticNetworkV1App } from "@/components/quantic-network-v1-app";

export default function Home() {
  return (
    <>
      <QuanticNetworkV1App />
      <Link className="qn-vault-fab" href="/vault" title="Sauvegarder ou restaurer mon identité Quantic">
        Identity Vault
      </Link>
    </>
  );
}
