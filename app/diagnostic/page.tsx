import { DesktopDiagnostics } from "@/components/desktop-diagnostics";

export const metadata = {
  title: "Diagnostic local — QuanticMail",
  description: "Vérifier l'identité locale et le relais Quantic du poste, sans divulguer de clés.",
};

export default function DiagnosticPage() {
  return <DesktopDiagnostics />;
}
