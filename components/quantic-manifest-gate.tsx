"use client";

import { ReactNode, useEffect, useState } from "react";
import { getLocalIdentity, saveLocalIdentity } from "@/lib/quantic/local-db";
import { verifyManifestBrowser } from "@/lib/quantic/manifest";
import { decideManifestSync } from "@/lib/quantic/manifest-sync-core.mjs";
import { manifestRelayPolicy } from "@/lib/quantic/manifest-relay-policy.mjs";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";
import {
  getRelayEndpoints,
  relayFetchJson,
  RelayHttpError,
} from "@/lib/quantic/relay-client";

type ManifestResponse = { manifest?: QuanticIdentityManifest; error?: string };

const IDENTITY_GATE_ENABLED =
  process.env.NEXT_PUBLIC_QUANTIC_IDENTITY_GATE_ENABLED === "true";

const DESKTOP_LOCAL_MANIFEST = process.env.NEXT_PUBLIC_QUANTIC_DESKTOP === "true";

function manifestRelays() {
  return manifestRelayPolicy({
    desktop: DESKTOP_LOCAL_MANIFEST,
    // Do not read user-configured public relays in the Windows local manifest
    // trust path. Their 403/404 responses are unrelated to the embedded relay.
    configured: DESKTOP_LOCAL_MANIFEST ? [] : getRelayEndpoints(),
  });
}

async function readRemoteManifest(canonicalAddress: string) {
  try {
    const { relays, retryStatuses } = manifestRelays();
    const { data } = await relayFetchJson<ManifestResponse>(
      relays,
      `/api/quantic/manifest?handle=${encodeURIComponent(canonicalAddress)}`,
      { cache: "no-store" },
      { retryStatuses },
    );
    return data.manifest ?? null;
  } catch (error) {
    if (error instanceof RelayHttpError && error.status === 404) return null;
    throw error;
  }
}

async function republishVerifiedManifest(manifest: QuanticIdentityManifest) {
  const { relays, retryStatuses } = manifestRelays();
  const { data } = await relayFetchJson<ManifestResponse>(
    relays,
    "/api/quantic/manifest",
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ manifest }),
      cache: "no-store",
    },
    { retryStatuses },
  );
  if (!data.manifest) throw new Error("Le relais Quantic n’a pas confirmé le manifeste.");
  return data.manifest;
}

export function QuanticManifestGate({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(!IDENTITY_GATE_ENABLED);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!IDENTITY_GATE_ENABLED) return;
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
          // Publish only a verified signed manifest, never to a remote
          // fallback in Windows. HTTP 401/403 always fails closed.
          const published = await republishVerifiedManifest(decision.manifest);
          if (!(await verifyManifestBrowser(published))) {
            throw new Error("Le manifeste Quantic republié a une signature invalide.");
          }
          const accepted = decideManifestSync(decision.manifest, published).manifest ?? published;
          await saveLocalIdentity({ ...local, manifest: accepted });
        }
        setReady(true);
      } catch (err) {
        if (DESKTOP_LOCAL_MANIFEST && err instanceof RelayHttpError && (err.status === 401 || err.status === 403)) {
          const gatewayRefusal = err.status === 403 && (
            err.message.startsWith("Quantic Mail Windows :") || err.message === "Erreur 403"
          );
          setError(gatewayRefusal
            ? `Le serveur Windows a bloqué la communication avec le relais local (HTTP 403). Ce refus ne prouve pas que le manifeste est invalide. Détail : ${err.message}. Ferme Quantic Mail complètement puis rouvre-le.`
            : `Le relais local Windows refuse le manifeste signé (HTTP ${err.status}). Aucune clé n'a été modifiée. Détail : ${err.message}`);
        } else {
          setError(err instanceof Error ? err.message : "Vérification du manifeste Quantic impossible.");
        }
      }
    })();
  }, []);

  if (!IDENTITY_GATE_ENABLED) {
    return <>{children}</>;
  }

  if (error) {
    return (
      <main className="qn-onboarding">
        <section className="qn-card qn-onboarding-card">
          <div className="qn-mark">Q</div>
          <p className="qn-kicker">QUANTIC SILLAGE</p>
          <h1>Synchronisation de sécurité bloquée.</h1>
          <p className="qn-error">{error}</p>
          <p className="qn-footnote">Votre boîte reste protégée. Aucune clé privée ni aucun manifeste non vérifié ne sera accepté.</p>
          <div className="qm-manifest-recovery" style={{display:"flex",gap:12,flexWrap:"wrap",marginTop:16}}>
            <button type="button" onClick={() => window.location.reload()} style={{padding:"12px 18px",borderRadius:12,border:"1px solid #87b6ef",background:"#1a4d96",color:"#fff",cursor:"pointer"}}>Réessayer l’accès</button>
            <a href="/network" style={{padding:"12px 18px",borderRadius:12,border:"1px solid #6582bb",color:"#d2e9ff"}}>Contrôler le relais</a>
            <a href="/vault" style={{padding:"12px 18px",borderRadius:12,border:"1px solid #6582bb",color:"#d2e9ff"}}>Vérifier mon coffre</a>
          </div>
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
