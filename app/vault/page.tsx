import { QuanticGlobalNav } from "@/components/quantic-global-nav";
import { IdentityVaultApp } from "@/components/identity-vault-app";

export const metadata = {
  title: "Quantic Identity Vault — QuanticMail",
  description: "Sauvegarder ou restaurer une identité Quantic chiffrée localement.",
};

export default function VaultPage() {
  return <><QuanticGlobalNav /><IdentityVaultApp /></>;
}
