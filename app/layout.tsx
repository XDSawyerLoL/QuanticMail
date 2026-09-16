import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "QuanticMail",
  description: "QuanticMail by Quantic Sillage",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
