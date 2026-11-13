"use client";

import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import {
  readVaultStatus,
  verifyUnlockedVault,
} from "@/lib/quantic/vault-bridge.mjs";

type State = {
  kind: "checking" | "unavailable" | "locked" | "confirm" | "verified" | "error";
  keyId?: string;
  label?: string;
  error?: string;
};

const IS_WINDOWS_DESKTOP = process.env.NEXT_PUBLIC_QUANTIC_DESKTOP === "true";

export function QuanticIdDesktopGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<State>({ kind: IS_WINDOWS_DESKTOP ? "checking" : "verified" });
  const verifiedKey = useRef<string | null>(null);
  const running = useRef(false);

  const check = useCallback(async (confirmHardware = false) => {
    if (running.current) return;
    running.current = true;
    try {
      const status = await readVaultStatus();
      if (!status.available) {
        verifiedKey.current = null;
        setState({ kind: "locked" });
        return;
      }
      if (status.keyId === verifiedKey.current) {
        setState({ kind: "verified", label: status.label, keyId: status.keyId ?? undefined });
        return;
      }
      if (status.hardwareMode && !confirmHardware) {
        setState({ kind: "confirm", label: status.label });
        return;
      }
      const verified = await verifyUnlockedVault(status);
      verifiedKey.current = verified.keyId;
      setState({ kind: "verified", label: verified.label, keyId: verified.keyId });
    } catch (error) {
      verifiedKey.current = null;
      const description = error instanceof Error ? error.message : "Service Quantic ID inaccessible.";
      const likelyUnavailable = /fetch|network|abort|timeout|ECONNREFUSED|failed/i.test(description);
      setState({ kind: likelyUnavailable ? "unavailable" : "error", error: description });
    } finally {
      running.current = false;
    }
  }, []);

  useEffect(() => {
    if (!IS_WINDOWS_DESKTOP) return;
    void check();
    const timer = window.setInterval(() => void check(), 12_000);
    return () => window.clearInterval(timer);
  }, [check]);

  if (!IS_WINDOWS_DESKTOP) return <>{children}</>;
  if (state.kind === "verified") return <>{children}</>;

  return (
    <main className="qn-onboarding qm-entry-page">
      <section className="qn-card qn-onboarding-card qm-entry-card">
        <div className="qm-entry-mark"><span className="qn-mark">Q</span><span className="qn-kicker">QUANTIC ID · ACCÈS LOCAL</span></div>
        {state.kind === "checking" ? (
          <>
            <h1>Recherche de Quantic ID…</h1>
            <p className="qn-lead">Vérification du logiciel Identity Vault présent sur ce PC.</p>
          </>
        ) : state.kind === "unavailable" ? (
          <>
            <h1>Identity Vault n'est pas détecté</h1>
            <p className="qn-lead">Ouvre l'application Quantic Identity Vault sur cet ordinateur. Quantic Mail recherchera son service local automatiquement, sans mot de passe.</p>
          </>
        ) : state.kind === "locked" ? (
          <>
            <h1>Quantic ID est verrouillé</h1>
            <p className="qn-lead">Déverrouille ton identité dans Identity Vault. Quantic Mail la reconnaîtra automatiquement et n'exigera aucun mot de passe de boîte.</p>
          </>
        ) : state.kind === "confirm" ? (
          <>
            <h1>Quantic ID détecté</h1>
            <p className="qn-lead">Ta clé matérielle Quantic est reconnue. Valide une preuve avec elle pour ouvrir Quantic Mail, sans divulguer ta clé privée.</p>
            <button type="button" onClick={() => void check(true)}>Vérifier mon Quantic ID</button>
          </>
        ) : (
          <>
            <h1>La vérification Quantic ID a échoué</h1>
            <p className="qn-lead">Le logiciel d'identité répond, mais sa preuve de signature n'a pas été vérifiée. La messagerie reste protégée.</p>
            <p className="qn-error">{state.error}</p>
          </>
        )}
        {state.kind !== "checking" && state.kind !== "confirm" && (
          <button type="button" onClick={() => void check()}>Vérifier à nouveau</button>
        )}
        <p className="qn-footnote">Identité et clés privées restent dans Identity Vault. Le service de vérification est local au PC (127.0.0.1).</p>
      </section>
    </main>
  );
}
