"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";
import {
  createDeviceCertificate,
  createPendingDevice,
  installDeviceCertificate,
  parseDeviceCertificate,
  parseDeviceRequest,
  serializeDeviceCertificate,
  serializeDeviceRequest,
  type PublicDeviceRequest,
} from "@/lib/quantic/device";
import {
  addDeviceToManifest,
  createInitialManifest,
  revokeDeviceInManifest,
  verifyManifestBrowser,
} from "@/lib/quantic/manifest";
import type { QuanticIdentityManifest, QuanticRevocation } from "@/lib/quantic/manifest-types";
import {
  clearPendingDevice,
  getLocalIdentity,
  getPendingDevice,
  saveLocalIdentity,
  savePendingDevice,
  type LocalIdentity,
  type LocalPendingDevice,
} from "@/lib/quantic/local-db";

type PublicDevice = {
  deviceId: string;
  label: string;
  publicKey: JsonWebKey;
  kind: "root" | "linked";
};

type ResolveResult = {
  canonicalAddress: string;
  devices: PublicDevice[];
  manifest?: QuanticIdentityManifest | null;
};

type RegistryStatus = {
  mode: "memory" | "github";
  configured: boolean;
  repository: string | null;
  branch: string | null;
  degraded: boolean;
  lastError: string | null;
};

class HttpError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
  }
}

function downloadTextFile(filename: string, text: string) {
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) throw new HttpError(data.error ?? `Erreur ${response.status}`, response.status);
  return data;
}

async function fetchManifest(canonicalAddress: string) {
  try {
    const result = await fetchJson<{ manifest: QuanticIdentityManifest }>(
      `/api/quantic/manifest?handle=${encodeURIComponent(canonicalAddress)}`,
    );
    if (!(await verifyManifestBrowser(result.manifest))) {
      throw new Error("Le manifeste distant a une signature invalide.");
    }
    return result.manifest;
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) return null;
    throw error;
  }
}

export function DevicesV1App() {
  const router = useRouter();
  const [identity, setIdentity] = useState<LocalIdentity | null>(null);
  const [pending, setPending] = useState<LocalPendingDevice | null>(null);
  const [devices, setDevices] = useState<PublicDevice[]>([]);
  const [manifest, setManifest] = useState<QuanticIdentityManifest | null>(null);
  const [registry, setRegistry] = useState<RegistryStatus | null>(null);
  const [canonical, setCanonical] = useState("");
  const [deviceLabel, setDeviceLabel] = useState("");
  const [requestFile, setRequestFile] = useState<File | null>(null);
  const [certificateFile, setCertificateFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function refreshRegistry() {
    try {
      setRegistry(await fetchJson<RegistryStatus>("/api/quantic/registry/status"));
    } catch {
      setRegistry(null);
    }
  }

  async function refreshDevices(local: LocalIdentity | null) {
    if (!local?.canonicalAddress) return;
    try {
      const result = await fetchJson<ResolveResult>(
        `/api/quantic/resolve?handle=${encodeURIComponent(local.canonicalAddress)}`,
      );
      setDevices(result.devices ?? []);
      let nextManifest = result.manifest ?? null;
      if (!nextManifest) nextManifest = await fetchManifest(local.canonicalAddress);
      if (nextManifest) {
        setManifest(nextManifest);
        if (!local.manifest || local.manifest.payload.sequence <= nextManifest.payload.sequence) {
          const next = { ...local, manifest: nextManifest };
          await saveLocalIdentity(next);
          setIdentity(next);
        }
      } else {
        setManifest(null);
      }
    } catch {
      setDevices([]);
      try {
        const nextManifest = await fetchManifest(local.canonicalAddress);
        setManifest(nextManifest);
      } catch {
        setManifest(null);
      }
    }
  }

  async function publishManifest(local: LocalIdentity, next: QuanticIdentityManifest) {
    const response = await fetchJson<{
      manifest: QuanticIdentityManifest;
      checkpoint: { persisted: boolean; mode: string; error?: string };
    }>("/api/quantic/manifest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ manifest: next }),
    });
    const saved = { ...local, manifest: response.manifest };
    await saveLocalIdentity(saved);
    setIdentity(saved);
    setManifest(response.manifest);
    await refreshRegistry();
    return response;
  }

  async function ensureRootManifest(local: LocalIdentity) {
    if (!local.canonicalAddress || !local.signingPrivateKey || local.role === "secondary") {
      throw new Error("Seul l’appareil maître peut activer le protocole V1.");
    }
    const remote = await fetchManifest(local.canonicalAddress);
    if (remote) return remote;
    const initial = await createInitialManifest(local);
    await publishManifest(local, initial);
    return initial;
  }

  useEffect(() => {
    void (async () => {
      try {
        const [local, localPending] = await Promise.all([getLocalIdentity(), getPendingDevice()]);
        setIdentity(local);
        setPending(localPending);
        if (localPending) {
          setCanonical(localPending.canonicalAddress);
          setDeviceLabel(localPending.deviceLabel);
        }
        await Promise.all([refreshDevices(local), refreshRegistry()]);
      } catch {
        setError("Impossible d’ouvrir le stockage local QuanticMail.");
      }
    })();
  }, []);

  async function activateV1() {
    if (!identity) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const next = await ensureRootManifest(identity);
      setManifest(next);
      setNotice(`Protocole V1 activé · manifeste #${next.payload.sequence}.`);
      await refreshDevices(identity);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Activation V1 impossible.");
    } finally {
      setBusy(false);
    }
  }

  async function prepareDevice(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (identity) throw new Error("Cet appareil possède déjà une identité Quantic locale.");
      const result = await createPendingDevice(canonical, deviceLabel);
      await savePendingDevice(result.pending);
      setPending(result.pending);
      downloadTextFile(
        `${result.pending.deviceLabel.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}-${result.pending.deviceId}.quantic-device-request`,
        serializeDeviceRequest(result.request),
      );
      setNotice("Demande créée. Transfère ce fichier vers l’appareil maître de l’identité.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Création de la demande impossible.");
    } finally {
      setBusy(false);
    }
  }

  async function approveDevice(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (!identity?.signingPrivateKey || identity.role === "secondary") {
        throw new Error("Seul l’appareil maître peut signer un certificat d’appareil.");
      }
      if (!requestFile) throw new Error("Choisissez un fichier .quantic-device-request.");
      if (requestFile.size > 250_000) throw new Error("Fichier de demande anormalement volumineux.");
      const request: PublicDeviceRequest = parseDeviceRequest(await requestFile.text());
      const certificate = await createDeviceCertificate(identity, request);
      const current = await ensureRootManifest(identity);
      const next = await addDeviceToManifest(identity, current, certificate);
      const published = await publishManifest(identity, next);
      downloadTextFile(
        `${request.deviceLabel.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}-${request.deviceId}.quantic-device-cert`,
        serializeDeviceCertificate(certificate),
      );
      setNotice(
        `Appareil autorisé dans le manifeste #${published.manifest.payload.sequence}. Certificat prêt pour ${request.deviceLabel}.`,
      );
      setRequestFile(null);
      await refreshDevices({ ...identity, manifest: published.manifest });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Autorisation impossible.");
    } finally {
      setBusy(false);
    }
  }

  async function installCertificate(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (identity) throw new Error("Une identité est déjà installée sur cet appareil.");
      const localPending = pending ?? (await getPendingDevice());
      if (!localPending) throw new Error("Crée d’abord une demande d’appareil sur ce navigateur.");
      if (!certificateFile) throw new Error("Choisissez le certificat signé par l’appareil maître.");
      if (certificateFile.size > 250_000) throw new Error("Certificat anormalement volumineux.");
      const certificate = parseDeviceCertificate(await certificateFile.text());
      const installed = await installDeviceCertificate(localPending, certificate);
      const remoteManifest = await fetchManifest(installed.canonicalAddress ?? certificate.payload.canonicalAddress);
      if (remoteManifest && !remoteManifest.payload.devices.some((device) => device.deviceId === installed.deviceId)) {
        throw new Error("Cet appareil n’apparaît pas dans le manifeste V1 signé.");
      }
      const withManifest = { ...installed, manifest: remoteManifest ?? undefined };
      await fetchJson("/api/quantic/devices/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ certificate, authToken: installed.authToken }),
      });
      await saveLocalIdentity(withManifest);
      await clearPendingDevice();
      setIdentity(withManifest);
      setPending(null);
      setNotice(`Appareil lié à ${installed.canonicalAddress}.`);
      router.push("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Installation du certificat impossible.");
    } finally {
      setBusy(false);
    }
  }

  async function revokeDevice(deviceId: string, reason: QuanticRevocation["reason"] = "user") {
    if (!identity || !manifest) return;
    setBusy(true);
    setError("");
    setNotice("");
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
      setNotice(`Appareil ${deviceId} révoqué dans le manifeste #${response.manifest.payload.sequence}.`);
      await refreshDevices(saved);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Révocation impossible.");
    } finally {
      setBusy(false);
    }
  }

  const activeManifestDevices = manifest?.payload.devices ?? [];
  const revocations = manifest?.payload.revocations ?? [];
  const isRoot = Boolean(identity?.signingPrivateKey && identity.role !== "secondary");

  return (
    <main className="qn-onboarding qn-devices-page">
      <section className="qn-card qn-devices-card">
        <div className="qn-vault-head">
          <div>
            <div className="qn-mark">Q</div>
            <p className="qn-kicker">QUANTIC NETWORK V1</p>
            <h1>Une identité. Plusieurs appareils. Une autorité cryptographique.</h1>
            <p className="qn-lead">
              Le manifeste signé décide quels appareils appartiennent à l’identité. Une révocation augmente sa séquence et ne peut pas être annulée par un état plus ancien.
            </p>
          </div>
          <Link className="qn-back-link" href="/">← QuanticMail</Link>
        </div>

        {identity ? (
          <>
            <div className="qn-v1-status-grid">
              <div className="qn-v1-status">
                <span>PROTOCOLE</span>
                <strong>{manifest ? `V1 · manifeste #${manifest.payload.sequence}` : "V0.9 compatible"}</strong>
              </div>
              <div className="qn-v1-status">
                <span>REGISTRE DURABLE</span>
                <strong>{registry?.mode === "github" && registry.configured ? "GitHub checkpoint" : "Mémoire locale du relais"}</strong>
              </div>
              <div className="qn-v1-status">
                <span>CET APPAREIL</span>
                <strong>{identity.role === "secondary" ? "Secondaire certifié" : "Maître"}</strong>
              </div>
            </div>

            {!manifest && isRoot && (
              <div className="qn-vault-warning">
                <strong>Activer le manifeste V1</strong>
                <p>Cette opération fait du manifeste signé l’autorité des appareils. Les anciens appareils V0.9 non présents dans le premier manifeste devront être liés à nouveau.</p>
                <button className="qn-dangerless-action" disabled={busy} onClick={() => void activateV1()}>
                  {busy ? "Activation…" : "Activer Quantic Network V1"}
                </button>
              </div>
            )}

            <div className="qn-vault-grid">
              <section className="qn-vault-section">
                <p className="qn-kicker">APPAREILS ACTIFS</p>
                <h2>{identity.canonicalAddress}</h2>
                <div className="qn-device-list">
                  {(manifest ? activeManifestDevices : devices).map((device) => (
                    <div className="qn-device-row qn-device-row-v1" key={device.deviceId}>
                      <div>
                        <b>{device.label}</b>
                        <small>{device.kind === "root" ? "maître" : "lié"}</small>
                      </div>
                      <code>{device.deviceId}</code>
                      {manifest && isRoot && device.kind === "linked" && (
                        <button className="qn-revoke" disabled={busy} onClick={() => void revokeDevice(device.deviceId, "user")}>
                          Révoquer
                        </button>
                      )}
                    </div>
                  ))}
                </div>

                {revocations.length > 0 && (
                  <div className="qn-revoked-list">
                    <strong>Révocations permanentes</strong>
                    {revocations.map((item) => (
                      <div className="qn-revoked-row" key={item.deviceId}>
                        <code>{item.deviceId}</code>
                        <span>{item.reason} · {new Date(item.revokedAt).toLocaleString("fr-FR")}</span>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              <section className="qn-vault-section">
                <p className="qn-kicker">AUTORISER</p>
                <h2>Signer un nouvel appareil</h2>
                {!isRoot ? (
                  <p className="qn-footnote">Cet appareil n’a pas la clé maîtresse. Il peut envoyer et recevoir, mais pas autoriser ou révoquer d’autres appareils.</p>
                ) : (
                  <form className="qn-vault-form" onSubmit={approveDevice}>
                    <label htmlFor="device-request">Demande créée sur le nouvel appareil</label>
                    <input id="device-request" type="file" accept=".quantic-device-request,application/json" onChange={(e) => setRequestFile(e.target.files?.[0] ?? null)} required />
                    <button disabled={busy}>{busy ? "Signature…" : "Signer et ajouter au manifeste"}</button>
                  </form>
                )}
              </section>
            </div>
          </>
        ) : (
          <div className="qn-vault-grid">
            <section className="qn-vault-section">
              <p className="qn-kicker">ÉTAPE 1</p>
              <h2>Préparer cet appareil</h2>
              <form className="qn-vault-form" onSubmit={prepareDevice}>
                <label htmlFor="canonical">Identité canonique à rejoindre</label>
                <input id="canonical" value={canonical} onChange={(e) => setCanonical(e.target.value)} placeholder="sansa~1a2b3c4d5e@quantic" required />
                <label htmlFor="device-label">Nom de cet appareil</label>
                <input id="device-label" value={deviceLabel} onChange={(e) => setDeviceLabel(e.target.value)} placeholder="Téléphone personnel" minLength={2} maxLength={48} required />
                <button disabled={busy}>{busy ? "Création…" : "Créer la demande"}</button>
              </form>
              {pending && <p className="qn-notice">Demande locale prête : {pending.deviceLabel} · {pending.deviceId}</p>}
            </section>

            <section className="qn-vault-section">
              <p className="qn-kicker">ÉTAPE 2</p>
              <h2>Installer le certificat signé</h2>
              <p className="qn-footnote">L’appareil maître signe la demande et ajoute cet appareil à son manifeste V1 avant de produire le certificat.</p>
              <form className="qn-vault-form" onSubmit={installCertificate}>
                <label htmlFor="device-certificate">Certificat signé</label>
                <input id="device-certificate" type="file" accept=".quantic-device-cert,application/json" onChange={(e) => setCertificateFile(e.target.files?.[0] ?? null)} required />
                <button disabled={busy || !pending}>{busy ? "Installation…" : "Lier cet appareil"}</button>
              </form>
            </section>
          </div>
        )}

        {(error || notice) && <p className={error ? "qn-error" : "qn-notice"}>{error || notice}</p>}
        {registry?.degraded && <p className="qn-error">Checkpoint durable dégradé : {registry.lastError}</p>}
        <div className="qn-vault-warning">
          <strong>Modèle V1</strong>
          <p>La clé maîtresse privée reste sur l’appareil maître. Les appareils secondaires ont leurs propres clés. Un appareil révoqué doit générer de nouvelles clés avant de pouvoir être autorisé à nouveau.</p>
        </div>
      </section>
    </main>
  );
}
