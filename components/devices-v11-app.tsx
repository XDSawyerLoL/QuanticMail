"use client";

import Image from "next/image";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useCallback, useEffect, useState } from "react";
import QRCode from "qrcode";
import {
  createDeviceCertificate,
  createPendingDevice,
  installDeviceCertificate,
  type PublicDeviceRequest,
} from "@/lib/quantic/device";
import {
  addDeviceToManifest,
  revokeDeviceInManifest,
  verifyManifestBrowser,
} from "@/lib/quantic/manifest";
import type { QuanticIdentityManifest, QuanticRevocation } from "@/lib/quantic/manifest-types";
import {
  clearPendingDevice,
  getLocalIdentity,
  getPendingDevice,
  importLocalMessages,
  listLocalMessages,
  saveLocalIdentity,
  savePendingDevice,
  type DeviceCertificate,
  type LocalIdentity,
  type LocalMessage,
  type LocalPendingDevice,
} from "@/lib/quantic/local-db";
import {
  decryptPairingPackage,
  encryptPairingPackage,
  randomPairingSecret,
  type EncryptedPairingPackage,
} from "@/lib/quantic/pairing-crypto.mjs";

type RegistryStatus = {
  mode: "memory" | "github";
  configured: boolean;
  repository: string | null;
  branch: string | null;
  degraded: boolean;
  lastError: string | null;
};

type PairingStatus = {
  inviteId: string;
  canonicalAddress: string;
  rootDeviceId: string;
  expiresAt: number;
  hasRequest: boolean;
  hasPackage: boolean;
  request: PublicDeviceRequest | null;
};

type PairingPackage = {
  certificate: DeviceCertificate;
  manifest: QuanticIdentityManifest;
  history: LocalMessage[];
  partialHistory: boolean;
};

type InviteView = {
  inviteId: string;
  secret: string;
  expiresAt: number;
  link: string;
  qr: string;
};

class HttpError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
  }
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) throw new HttpError(data.error ?? `Erreur ${response.status}`, response.status);
  return data;
}

function bearer(identity: LocalIdentity) {
  return { authorization: `Bearer ${identity.authToken}` };
}

function fragmentSecret() {
  if (typeof window === "undefined") return "";
  const value = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("secret");
  return value ?? "";
}

export function DevicesV11App() {
  const router = useRouter();
  const [identity, setIdentity] = useState<LocalIdentity | null>(null);
  const [manifest, setManifest] = useState<QuanticIdentityManifest | null>(null);
  const [registry, setRegistry] = useState<RegistryStatus | null>(null);
  const [invite, setInvite] = useState<InviteView | null>(null);
  const [pairing, setPairing] = useState<PairingStatus | null>(null);
  const [pending, setPending] = useState<LocalPendingDevice | null>(null);
  const [deviceLabel, setDeviceLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const refreshManifest = useCallback(async (local: LocalIdentity | null) => {
    if (!local?.canonicalAddress) return;
    try {
      const result = await fetchJson<{ manifest: QuanticIdentityManifest }>(
        `/api/quantic/manifest?handle=${encodeURIComponent(local.canonicalAddress)}`,
      );
      if (!(await verifyManifestBrowser(result.manifest))) throw new Error("Manifeste distant invalide.");
      setManifest(result.manifest);
      if (!local.manifest || local.manifest.payload.sequence <= result.manifest.payload.sequence) {
        const next = { ...local, manifest: result.manifest };
        await saveLocalIdentity(next);
        setIdentity(next);
      }
    } catch (err) {
      if (!(err instanceof HttpError && err.status === 404)) throw err;
    }
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        const [local, localPending, registryState] = await Promise.all([
          getLocalIdentity(),
          getPendingDevice(),
          fetchJson<RegistryStatus>("/api/quantic/registry/status").catch(() => null),
        ]);
        setIdentity(local);
        setPending(localPending);
        setRegistry(registryState);
        await refreshManifest(local);

        if (!local && typeof window !== "undefined") {
          const inviteId = new URL(window.location.href).searchParams.get("pair") ?? "";
          const secret = fragmentSecret();
          if (inviteId && secret) {
            const status = await fetchJson<PairingStatus>("/api/quantic/pairing/status", {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ inviteId, secret }),
            });
            setPairing(status);
          }
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Initialisation du pairing impossible.");
      }
    })();
  }, [refreshManifest]);

  useEffect(() => {
    if (!invite) return;
    const timer = window.setInterval(() => {
      void (async () => {
        try {
          const status = await fetchJson<PairingStatus>("/api/quantic/pairing/status", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ inviteId: invite.inviteId, secret: invite.secret }),
          });
          setPairing(status);
        } catch {
          // Expiry is surfaced when the user acts; polling stays quiet.
        }
      })();
    }, 2000);
    return () => window.clearInterval(timer);
  }, [invite]);

  useEffect(() => {
    if (identity || !pairing?.hasPackage || !pending) return;
    const inviteId = pairing.inviteId;
    const secret = fragmentSecret();
    if (!secret) return;
    void (async () => {
      try {
        setBusy(true);
        const response = await fetchJson<{ package: EncryptedPairingPackage }>("/api/quantic/pairing/package", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ mode: "take", inviteId, secret }),
        });
        const payload = await decryptPairingPackage<PairingPackage>(secret, inviteId, response.package);
        if (!(await verifyManifestBrowser(payload.manifest))) throw new Error("Manifeste reçu par pairing invalide.");
        const installed = await installDeviceCertificate(pending, payload.certificate);
        if (!payload.manifest.payload.devices.some((device) => device.deviceId === installed.deviceId)) {
          throw new Error("Le nouvel appareil n’est pas autorisé dans le manifeste signé.");
        }
        const withManifest = { ...installed, manifest: payload.manifest };
        await fetchJson("/api/quantic/devices/register", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ certificate: payload.certificate, authToken: installed.authToken }),
        });
        const imported = await importLocalMessages(payload.history ?? []);
        await saveLocalIdentity(withManifest);
        await clearPendingDevice();
        setIdentity(withManifest);
        setPending(null);
        setNotice(
          `Appareil lié · ${imported.imported} message(s) importé(s)${payload.partialHistory ? " · historique partiel" : ""}.`,
        );
        window.history.replaceState(null, "", "/devices");
        router.push("/");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Installation du pairing impossible.");
      } finally {
        setBusy(false);
      }
    })();
  }, [identity, pairing, pending, router]);

  async function createQrInvite() {
    if (!identity?.canonicalAddress || !identity.deviceId || identity.role === "secondary") return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const secret = randomPairingSecret();
      const created = await fetchJson<{ inviteId: string; expiresAt: number }>("/api/quantic/pairing/invite", {
        method: "POST",
        headers: { "content-type": "application/json", ...bearer(identity) },
        body: JSON.stringify({
          canonicalAddress: identity.canonicalAddress,
          rootDeviceId: identity.deviceId,
          secret,
        }),
      });
      const link = `${window.location.origin}/devices?pair=${encodeURIComponent(created.inviteId)}#secret=${secret}`;
      const qr = await QRCode.toDataURL(link, { width: 320, margin: 1, errorCorrectionLevel: "M" });
      setInvite({ ...created, secret, link, qr });
      setPairing(null);
      setNotice("Invitation QR créée. Elle expire dans 10 minutes.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Création du QR impossible.");
    } finally {
      setBusy(false);
    }
  }

  async function joinPairing(event: FormEvent) {
    event.preventDefault();
    if (!pairing) return;
    setBusy(true);
    setError("");
    try {
      const secret = fragmentSecret();
      if (!secret) throw new Error("Secret de pairing absent du lien.");
      const result = await createPendingDevice(pairing.canonicalAddress, deviceLabel);
      await savePendingDevice(result.pending);
      await fetchJson("/api/quantic/pairing/request", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ inviteId: pairing.inviteId, secret, request: result.request }),
      });
      setPending(result.pending);
      setNotice("Demande envoyée. Valide ce nouvel appareil sur l’appareil maître.");
      const status = await fetchJson<PairingStatus>("/api/quantic/pairing/status", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ inviteId: pairing.inviteId, secret }),
      });
      setPairing(status);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Demande de pairing impossible.");
    } finally {
      setBusy(false);
    }
  }

  async function approvePairing() {
    if (!identity || !invite || !pairing?.request || !manifest) return;
    setBusy(true);
    setError("");
    try {
      const certificate = await createDeviceCertificate(identity, pairing.request);
      const nextManifest = await addDeviceToManifest(identity, manifest, certificate);
      const published = await fetchJson<{ manifest: QuanticIdentityManifest }>("/api/quantic/manifest", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ manifest: nextManifest }),
      });
      let history = await listLocalMessages();
      let partialHistory = false;
      let encrypted = await encryptPairingPackage(invite.secret, invite.inviteId, {
        certificate,
        manifest: published.manifest,
        history,
        partialHistory,
      } satisfies PairingPackage);
      const maxBytes = 4 * 1024 * 1024;
      while (new TextEncoder().encode(JSON.stringify(encrypted)).byteLength > maxBytes && history.length > 1) {
        history = history.slice(0, Math.max(1, Math.floor(history.length * 0.75)));
        partialHistory = true;
        encrypted = await encryptPairingPackage(invite.secret, invite.inviteId, {
          certificate,
          manifest: published.manifest,
          history,
          partialHistory,
        } satisfies PairingPackage);
      }
      if (new TextEncoder().encode(JSON.stringify(encrypted)).byteLength > maxBytes) {
        throw new Error("Le paquet de pairing reste trop volumineux après réduction de l’historique.");
      }
      await fetchJson("/api/quantic/pairing/package", {
        method: "POST",
        headers: { "content-type": "application/json", ...bearer(identity) },
        body: JSON.stringify({
          mode: "put",
          canonicalAddress: identity.canonicalAddress,
          rootDeviceId: identity.deviceId,
          inviteId: invite.inviteId,
          secret: invite.secret,
          package: encrypted,
        }),
      });
      const saved = { ...identity, manifest: published.manifest };
      await saveLocalIdentity(saved);
      setIdentity(saved);
      setManifest(published.manifest);
      setNotice(`Appareil autorisé · manifeste #${published.manifest.payload.sequence}${partialHistory ? " · historique partiel" : ""}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Autorisation du nouvel appareil impossible.");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(deviceId: string, reason: QuanticRevocation["reason"] = "user") {
    if (!identity || !manifest || identity.role === "secondary") return;
    setBusy(true);
    setError("");
    try {
      const next = await revokeDeviceInManifest(identity, manifest, deviceId, reason);
      const response = await fetchJson<{ manifest: QuanticIdentityManifest }>("/api/quantic/devices/revoke", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ manifest: next }),
      });
      const saved = { ...identity, manifest: response.manifest };
      await saveLocalIdentity(saved);
      setIdentity(saved);
      setManifest(response.manifest);
      setNotice(`Appareil révoqué · manifeste #${response.manifest.payload.sequence}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Révocation impossible.");
    } finally {
      setBusy(false);
    }
  }

  if (!identity) {
    return (
      <main className="qn-onboarding qn-devices-page">
        <section className="qn-card qn-devices-card">
          <div className="qn-vault-head">
            <div>
              <div className="qn-mark">Q</div>
              <p className="qn-kicker">QUANTIC NETWORK V1.1</p>
              <h1>Associer cet appareil.</h1>
              <p className="qn-lead">Le QR transporte un secret de pairing dans le fragment local du lien. Le serveur ne conserve que l’état temporaire du rendez-vous.</p>
            </div>
            <Link className="qn-back-link" href="/">← QuanticMail</Link>
          </div>

          {pairing ? (
            <section className="qn-vault-section">
              <p className="qn-kicker">PAIRING QR</p>
              <h2>{pairing.canonicalAddress}</h2>
              {!pending ? (
                <form className="qn-vault-form" onSubmit={joinPairing}>
                  <label htmlFor="pair-label">Nom de cet appareil</label>
                  <input id="pair-label" value={deviceLabel} onChange={(event) => setDeviceLabel(event.target.value)} placeholder="Téléphone personnel" minLength={2} maxLength={48} required />
                  <button disabled={busy}>{busy ? "Préparation…" : "Demander l’autorisation"}</button>
                </form>
              ) : (
                <p className="qn-notice">Demande prête pour {pending.deviceLabel}. En attente de validation sur l’appareil maître…</p>
              )}
            </section>
          ) : (
            <div className="qn-vault-warning">
              <strong>Aucun lien QR détecté</strong>
              <p>Scanne le QR affiché par l’appareil maître, ou utilise le pairing par fichiers.</p>
            </div>
          )}

          {(error || notice) && <p className={error ? "qn-error" : "qn-notice"}>{error || notice}</p>}
          <Link className="qn-secondary-link" href="/devices/files">Pairing par fichiers (secours)</Link>
        </section>
      </main>
    );
  }

  const isRoot = identity.role !== "secondary" && Boolean(identity.signingPrivateKey);
  const activeDevices = manifest?.payload.devices ?? [];

  return (
    <main className="qn-onboarding qn-devices-page">
      <section className="qn-card qn-devices-card">
        <div className="qn-vault-head">
          <div>
            <div className="qn-mark">Q</div>
            <p className="qn-kicker">QUANTIC NETWORK V1.1</p>
            <h1>Appareils & pairing sécurisé.</h1>
            <p className="qn-lead">Une identité, des clés indépendantes par appareil, révocation signée et historique bootstrap chiffré.</p>
          </div>
          <Link className="qn-back-link" href="/">← QuanticMail</Link>
        </div>

        <div className="qn-v1-status-grid">
          <div className="qn-v1-status"><span>IDENTITÉ</span><strong>{identity.canonicalAddress}</strong></div>
          <div className="qn-v1-status"><span>MANIFESTE</span><strong>{manifest ? `#${manifest.payload.sequence}` : "indisponible"}</strong></div>
          <div className="qn-v1-status"><span>REGISTRE</span><strong>{registry?.configured ? "GitHub durable" : "mémoire"}</strong></div>
        </div>

        <div className="qn-vault-grid">
          <section className="qn-vault-section">
            <p className="qn-kicker">APPAREILS ACTIFS</p>
            <div className="qn-device-list">
              {activeDevices.map((device) => (
                <div className="qn-device-row qn-device-row-v1" key={device.deviceId}>
                  <div><b>{device.label}</b><small>{device.kind === "root" ? "maître" : "lié"}</small></div>
                  <code>{device.deviceId}</code>
                  {isRoot && device.kind === "linked" && (
                    <button className="qn-revoke" disabled={busy} onClick={() => void revoke(device.deviceId)}>Révoquer</button>
                  )}
                </div>
              ))}
            </div>
          </section>

          <section className="qn-vault-section">
            <p className="qn-kicker">PAIRING QR</p>
            {isRoot ? (
              <>
                {!invite ? (
                  <button className="qn-dangerless-action" disabled={busy || !manifest} onClick={() => void createQrInvite()}>
                    {busy ? "Création…" : "Créer un QR d’association"}
                  </button>
                ) : (
                  <div className="qn-pairing-qr">
                    <Image src={invite.qr} width={320} height={320} alt="QR de pairing QuanticMail" unoptimized />
                    <p>Expire à {new Date(invite.expiresAt).toLocaleTimeString("fr-FR")}</p>
                    <button type="button" onClick={() => void navigator.clipboard.writeText(invite.link)}>Copier le lien</button>
                    {pairing?.request && (
                      <div className="qn-vault-warning">
                        <strong>{pairing.request.deviceLabel}</strong>
                        <code>{pairing.request.deviceId}</code>
                        <button disabled={busy} onClick={() => void approvePairing()}>{busy ? "Chiffrement…" : "Autoriser cet appareil"}</button>
                      </div>
                    )}
                  </div>
                )}
              </>
            ) : (
              <p className="qn-footnote">Seul l’appareil maître peut autoriser de nouveaux appareils.</p>
            )}
          </section>
        </div>

        {(error || notice) && <p className={error ? "qn-error" : "qn-notice"}>{error || notice}</p>}
        {registry?.degraded && <p className="qn-error">Registre durable dégradé : {registry.lastError}</p>}
        <Link className="qn-secondary-link" href="/devices/files">Pairing par fichiers (secours)</Link>
      </section>
    </main>
  );
}
