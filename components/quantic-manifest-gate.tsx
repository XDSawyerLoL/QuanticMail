"use client";

import { ReactNode, useEffect, useState } from "react";
import { getLocalIdentity, saveLocalIdentity } from "@/lib/quantic/local-db";
import { verifyManifestBrowser } from "@/lib/quantic/manifest";
import { decideManifestSync } from "@/lib/quantic/manifest-sync-core.mjs";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";

type ManifestResponse = { manifest?: QuanticIdentityManifest; error?: string };

export function QuanticManifestGate({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const local = await getLocalIdentity();
        if (!local?.canonicalAddress) {
          setReady(true);
          return;
        }
        if (local.manifest && !(await verifyManifestBrowser(local.manifest))) {
          throw new Error("Le manifeste local Quantic a une signature invalide.");
        }

        const response = await fetch(
          `/api/quantic/manifest?handle=${encodeURIComponent(local.canonicalAddress)}`,
          { cache: "no-store" },
        );
        let remote: QuanticIdentityManifest | null = null;
        if (response.ok) {
          const data = (await response.json()) as ManifestResponse;
          remote = data.manifest ?? null;
          if (!remote || !(await verifyManifestBrowser(remote))) {
            throw new Error("Le manifeste Quantic distant a une signature invalide.");
          }
          if (remote.payload.canonicalAddress !== local.canonicalAddress) {
            throw new Error("Le manifeste Quantic distant vise une autre identité.");
          }
        } else if (response.status !== 404) {
          const data = (await response.json().catch(() => ({}))) as ManifestResponse;
          throw new Error(data.error ?? `Impossible de vérifier le manifeste Quantic (${response.status}).`);
        }

        const decision = decideManifestSync(local.manifest ?? null, remote);
        if (decision.action === "adopt-remote" && decision.manifest) {
          await saveLocalIdentity({ ...local, manifest: decision.manifest });
        }
        setReady(true);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Vérification du manifeste Quantic impossible.");
      }
    })();
  }, []);

  if (error) {
    return (
      <main className="qn-onboarding">
        <section className="qn-card qn-onboarding-card">
          <div className="qn-mark">Q</div>
          <p className="qn-kicker">QUANTIC SILLAGE</p>
          <h1>Synchronisation de sécurité bloquée.</h1>
          <p className="qn-error">{error}</p>
          <p className="qn-footnote">Aucun manifeste local n’a été republié. Vérifie le registre avant de continuer.</p>
        </section>
      </main>
    );
  }

  if (!ready) {
    return (
      <main className="qn-onboarding">
        <section className="qn-card qn-onboarding-card">
          <div className="qn-mark">Q</div>
          <p className="qn-kicker">QUANTIC SILLAGE</p>
          <h1>Vérification du manifeste…</h1>
          <p className="qn-footnote">QuanticMail compare l’état local avec l’autorité disponible avant d’ouvrir la session.</p>
        </section>
      </main>
    );
  }

  return <>{children}</>;
}
