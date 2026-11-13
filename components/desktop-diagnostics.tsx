"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { getLocalIdentity } from "@/lib/quantic/local-db";
import { getRelayEndpoints } from "@/lib/quantic/relay-client";

type Report = {
  identity: string;
  identityRole: string;
  relay: string;
  relayId: string;
  relayConfigured: number;
  checkedAt: string;
};

export function DesktopDiagnostics() {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(true);

  const check = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const identity = await getLocalIdentity();
      let relay = "Injoignable";
      let relayId = "";
      try {
        const response = await fetch("/api/quantic/health", { cache: "no-store" });
        const data = await response.json() as { ok?: boolean; relayId?: string; protocol?: string };
        if (!response.ok || !data.ok || data.protocol !== "quantic-relay/1") {
          relay = `Erreur HTTP ${response.status}`;
        } else {
          relay = "Fonctionnel sur ce PC";
          relayId = data.relayId ?? "";
        }
      } catch {
        relay = "Injoignable";
      }
      setReport({
        identity: identity?.canonicalAddress ?? "Aucune identité importée sur ce PC",
        identityRole: !identity ? "non configurée" : identity.role === "secondary" ? "appareil lié" : "identité principale",
        relay, relayId,
        relayConfigured: getRelayEndpoints().filter((entry) => entry.enabled && Boolean(entry.baseUrl)).length,
        checkedAt: new Date().toLocaleString("fr-FR"),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Échec de lecture du stockage local");
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => { void check(); }, [check]);

  return (
    <main className="qn-onboarding qn-vault-page">
      <section className="qn-card qn-vault-card">
        <div className="qn-vault-head">
          <div>
            <p className="qn-kicker">QUANTIC MAIL WINDOWS · DIAGNOSTIC LOCAL</p>
            <h1>Vérification de l'identité et du relais</h1>
            <p className="qn-lead">Seules des informations de statut sont affichées. Aucune clé privée, aucun mot de passe ni contenu de message n'est transmis.</p>
          </div>
          <Link className="qn-back-link" href="/">Retour à la messagerie</Link>
        </div>
        {busy && <p className="qn-footnote">Vérification locale…</p>}
        {error && <p className="qn-error">{error}</p>}
        {report && (
          <div className="qn-vault-grid single">
            <section className="qn-vault-section">
              <p className="qn-kicker">IDENTITÉ SUR CE PC</p>
              <h2>{report.identity}</h2>
              <p className="qn-footnote">Statut : {report.identityRole}</p>
              {report.identityRole === "non configurée" && (
                <p className="qn-notice">L'identité utilisée sur le site web n'est pas automatiquement présente dans l'application. Exportez votre .quantic-vault depuis le navigateur d'origine, puis restaurez-le ici. Ne créez pas une nouvelle identité avec le même pseudo.</p>
              )}
              <Link href="/vault">Ouvrir Identity Vault</Link>
            </section>
            <section className="qn-vault-section">
              <p className="qn-kicker">RELAIS EMBARQUÉ</p>
              <h2>{report.relay}</h2>
              <p className="qn-footnote">Identifiant du relais : {report.relayId || "indisponible"}</p>
              <p className="qn-footnote">Relais distants configurés : {report.relayConfigured}. Un relais local fonctionnel ne prouve pas que les autres utilisateurs sont joignables. Sur un réseau isolé, leurs identités et leurs messages ne sont pas automatiquement visibles.</p>
              <Link href="/network">Voir les relais réseau</Link>
            </section>
          </div>
        )}
        <button type="button" onClick={() => void check()} disabled={busy}>Relancer le diagnostic</button>
        {report && <p className="qn-footnote">Dernière vérification : {report.checkedAt}</p>}
      </section>
    </main>
  );
}
