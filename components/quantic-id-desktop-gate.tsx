"use client";

import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import { getLocalIdentity, saveLocalIdentity } from "@/lib/quantic/local-db";
import {
  bindMailboxToQuanticId,
  decideQuanticIdMailboxAccess,
} from "@/lib/quantic/quantic-id-mail-binding.mjs";
import {
  readVaultStatus,
  verifyUnlockedVault,
} from "@/lib/quantic/vault-bridge.mjs";

type State = {
  kind: "checking" | "unavailable" | "locked" | "confirm" | "verified" | "unbound" | "mismatch" | "error";
  keyId?: string;
  label?: string;
  mailboxAddress?: string;
  error?: string;
};

const IS_WINDOWS_DESKTOP = process.env.NEXT_PUBLIC_QUANTIC_DESKTOP === "true";

export function QuanticIdDesktopGate({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [state, setState] = useState<State>({ kind: IS_WINDOWS_DESKTOP ? "checking" : "verified" });
  const verifiedKey = useRef<string | null>(null);
  const running = useRef(false);
  const [binding, setBinding] = useState(false);

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
      if (status.keyId !== verifiedKey.current) {
        if (status.hardwareMode && !confirmHardware) {
          setState({ kind: "confirm", label: status.label });
          return;
        }
        const verified = await verifyUnlockedVault(status);
        verifiedKey.current = verified.keyId;
      }

      const localMail = await getLocalIdentity();
      const result = decideQuanticIdMailboxAccess(localMail, verifiedKey.current);
      if (result.kind === "mismatch") {
        setState({ kind: "mismatch", label: status.label });
      } else if (result.kind === "unbound") {
        setState({ kind: "unbound", label: status.label, keyId: verifiedKey.current ?? undefined,
          mailboxAddress: result.address });
      } else if (result.kind === "invalid") {
        throw new Error("Quantic ID local invalide.");
      } else {
        setState({ kind: "verified", label: status.label, keyId: verifiedKey.current ?? undefined });
      }
    } catch (error) {
      verifiedKey.current = null;
      const description = error instanceof Error ? error.message : "Service Quantic ID inaccessible.";
      const likelyUnavailable = /fetch|network|abort|timeout|ECONNREFUSED|failed/i.test(description);
      setState({ kind: likelyUnavailable ? "unavailable" : "error", error: description });
    } finally {
      running.current = false;
    }
  }, []);

  const confirmBinding = useCallback(async () => {
    if (binding) return;
    setBinding(true);
    try {
      const status = await readVaultStatus();
      const verified = await verifyUnlockedVault(status);
      const currentMail = await getLocalIdentity();
      const linked = bindMailboxToQuanticId(currentMail, verified.keyId);
      if (linked !== currentMail) await saveLocalIdentity(linked);
      verifiedKey.current = verified.keyId;
      setState({ kind: "verified", label: verified.label, keyId: verified.keyId });
    } catch (error) {
      setState({ kind: "error",
        error: error instanceof Error ? error.message : "Association de la boîte impossible." });
    } finally {
      setBinding(false);
    }
  }, [binding]);

  useEffect(() => {
    if (!IS_WINDOWS_DESKTOP) return;
    void check();
    const timer = window.setInterval(() => void check(), 12_000);
    return () => window.clearInterval(timer);
  }, [check, pathname]);

  if (!IS_WINDOWS_DESKTOP || state.kind === "verified") return <>{children}</>;

  return (
    <main className="qn-onboarding qm-entry-page">
      <section className="qn-card qn-onboarding-card qm-entry-card">
        <div className="qm-entry-mark"><span className="qn-mark">Q</span><span className="qn-kicker">QUANTIC ID · ACCÈS UNIQUE</span></div>
        {state.kind === "checking" ? (
          <>
            <h1>Vérification de Quantic ID…</h1>
            <p className="qn-lead">Connexion locale au logiciel Identity Vault.</p>
          </>
        ) : state.kind === "unavailable" ? (
          <>
            <h1>Quantic ID introuvable</h1>
            <p className="qn-lead">Ouvre Quantic Identity Vault sur ton ordinateur. Quantic Mail reconnaîtra automatiquement ton identité, sans mot de passe.</p>
          </>
        ) : state.kind === "locked" ? (
          <>
            <h1>Quantic ID verrouillé</h1>
            <p className="qn-lead">Déverrouille Identity Vault. C'est ton unique identification pour les produits Quantic.</p>
          </>
        ) : state.kind === "confirm" ? (
          <>
            <h1>Quantic ID détecté</h1>
            <p className="qn-lead">Valide la présence de ta Quantic Hardware Key pour ouvrir la messagerie, sans exposer sa clé privée.</p>
            <button type="button" onClick={() => void check(true)}>Valider mon Quantic ID</button>
          </>
        ) : state.kind === "unbound" ? (
          <>
            <h1>Relier cette boîte à Quantic ID</h1>
            <p className="qn-lead">Une boîte existe déjà sur ce PC : <strong>{state.mailboxAddress}</strong>. Elle n'est pas encore associée à ton Quantic ID.</p>
            <p className="qn-notice">Confirme une seule fois cette association. Ensuite, déverrouiller ton Quantic ID suffira pour retrouver cette boîte. Aucune nouvelle adresse ni aucun nouveau mot de passe ne seront créés.</p>
            <button type="button" disabled={binding} onClick={() => void confirmBinding()}>{binding ? "Association…" : "Associer cette boîte à mon Quantic ID"}</button>
          </>
        ) : state.kind === "mismatch" ? (
          <>
            <h1>Cette boîte appartient à un autre Quantic ID</h1>
            <p className="qn-lead">Le coffre déverrouillé ne correspond pas au Quantic ID associé à la boîte conservée sur cet ordinateur. Ouvre le bon Identity Vault avant de continuer.</p>
            <p className="qn-notice">Pour ta sécurité, le logiciel ne remplacera pas automatiquement le propriétaire enregistré et ne supprimera pas tes messages.</p>
          </>
        ) : (
          <>
            <h1>Quantic ID n'a pas pu être vérifié</h1>
            <p className="qn-lead">La signature d'Identity Vault doit être vérifiée localement pour ouvrir la boîte.</p>
            <p className="qn-error" role="alert">{state.error}</p>
          </>
        )}
        {state.kind !== "checking" && state.kind !== "confirm" && state.kind !== "unbound" && (
          <button type="button" onClick={() => void check()}>Vérifier à nouveau</button>
        )}
        <p className="qn-footnote">Quantic ID est le compte unique. Les clés de chiffrement des messages restent séparées pour des raisons de sécurité, mais ne nécessitent pas de second compte.</p>
      </section>
    </main>
  );
}
