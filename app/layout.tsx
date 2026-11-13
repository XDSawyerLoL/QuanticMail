import type { Metadata } from "next";
import "./globals.css";
import "./quantic.css";
import { QuanticGlobalNav } from "@/components/quantic-global-nav";
import { QuanticIdDesktopGate } from "@/components/quantic-id-desktop-gate";

export const metadata: Metadata = {
  title: "QuanticMail — Quantic Network",
  description: "Messagerie locale et chiffrée du réseau Quantic, par Quantic Sillage",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="fr">
      <body><QuanticIdDesktopGate><QuanticGlobalNav />{children}</QuanticIdDesktopGate></body>
    </html>
  );
}
