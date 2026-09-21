"use client";

import { ReactNode, useEffect, useState } from "react";
import { getLocalIdentity, saveLocalIdentity } from "@/lib/quantic/local-db";
import { verifyManifestBrowser } from "@/lib/quantic/manifest";
import { decideManifestSync } from "@/lib/quantic/manifest-sync-core.mjs";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";
import {
  getRelayEndpoints,
  relayFetchJson,
  RelayHttpError,
  type RelayEndpoint,
} from "@/lib/quantic/relay-client";

type ManifestResponse = { manifest?: QuanticIdentityManifest; error?: string };

function manifestRelayCandidates(): RelayEndpoint[] {
  const sameOrigin: RelayEndpoint = {
    id: "quantic-hostinger",
    label: "Quantic Hostinger",
    baseUrl: "",
    priority: 5,
    enabled: true,
  };
  const configured = getRelayEndpoints();
  const seen = new Set<string>(["same-origin"]);
  const result: RelayEndpoint[] = [sameOrigin];
  for (const relay of configured) {
    const key = relay.baseUrl || "same-origin";
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(relay);
  }
  return result;
}

async function readRemoteManifest(canonicalAddress: string) {
  try {
    const { data } = await relayFetchJson<ManifestResponse>(
      manifestRelayCandidates(),
      `/api/quantic/manifest?handle=${encodeURIComponent(canonicalAddress)}`,
      { cache: "no-store" },
      { retryStatuses: [403, 404] },
    );
    return data.manifest ?? null;
  } catch (error) {
    if (error instanceof RelayHttpError && error.status === 404) return null;
    throw error;
  }
}

async function republishVerifiedManifest(manifest: QuanticIdentityManifest) {
  const { data } = await relayFetchJson<ManifestResponse>(
    manifestRelayCandidates(),
    "/api/quantic/manifest",
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ manifest }),
      cache: "no-store",
    },
    { retryStatuses: [403, 404] },
  );
  if (!data.manifest) throw new Error("Le relais Quantic n’a pas confirmé le manifeste.");
  return data.manifest;
}

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

        const remote = await readRemoteManifest(local.canonicalAddress);
        if (remote) {
          if (!(await verifyManifestBrowser(remote))) {
            throw new Error("Le manifeste Quantic distant a une signature invalide.");
          }
          if (remote.payload.canonicalAddress !== local.canonicalAddress) {
            throw new Error("Le manifeste Quantic distant vise une autre identité.");
          }
        }

        const decision = decideManifestSync(local.manifest ?? null, remote);
        if (decision.action === "adopt-remote" && decision.manifest) {
          await saveLocalIdentity({ ...local, manifest: decision.manifest });
        } else if (decision.action === "publish-local" && decision.manifest) {
          // Only a manifest already verified locally is republished. A 401/403
          // from every trusted relay still fails closed before reaching this path.
          const published = await republishVerifiedManifest(decision.manifest);
          if (!(await verifyManifestBrowser(published))) {
            throw new Error("Le manifeste Quantic republié a une signature invalide.");
          }
          const accepted = decideManifestSync(decision.manifest, published).manifest ?? published;
          await saveLocalIdentity({ ...local, manifest: accepted });
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
