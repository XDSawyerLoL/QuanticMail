import type { Metadata } from "next";
import "./globals.css";
import "./quantic.css";
import { QuanticGlobalNav } from "@/components/quantic-global-nav";

export const metadata: Metadata = {
  title: "QuanticMail — Quantic Network",
  description: "Messagerie locale et chiffrée du réseau Quantic, par Quantic Sillage",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="fr">
      <body><QuanticGlobalNav />{children}</body>
    </html>
  );
}
