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
};

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
  if (!response.ok) throw new Error(data.error ?? `Erreur ${response.status}`);
  return data;
}

export function DevicesApp() {
  const router = useRouter();
  const [identity, setIdentity] = useState<LocalIdentity | null>(null);
  const [pending, setPending] = useState<LocalPendingDevice | null>(null);
  const [devices, setDevices] = useState<PublicDevice[]>([]);
  const [canonical, setCanonical] = useState("");
  const [deviceLabel, setDeviceLabel] = useState("");
  const [requestFile, setRequestFile] = useState<File | null>(null);
  const [certificateFile, setCertificateFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function refreshDevices(local: LocalIdentity | null) {
    if (!local?.canonicalAddress) return;
    try {
      const result = await fetchJson<ResolveResult>(
        `/api/quantic/resolve?handle=${encodeURIComponent(local.canonicalAddress)}`,
      );
      setDevices(result.devices ?? []);
    } catch {
      setDevices([]);
    }
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
        await refreshDevices(local);
      } catch {
        setError("Impossible d’ouvrir le stockage local QuanticMail.");
      }
    })();
  }, []);

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
      downloadTextFile(
        `${request.deviceLabel.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}-${request.deviceId}.quantic-device-cert`,
        serializeDeviceCertificate(certificate),
      );
      setNotice(`Certificat signé pour ${request.deviceLabel}. Renvoie ce fichier vers le nouvel appareil.`);
      setRequestFile(null);
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
      await fetchJson("/api/quantic/devices/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ certificate, authToken: installed.authToken }),
      });
      await saveLocalIdentity(installed);
      await clearPendingDevice();
      setIdentity(installed);
      setPending(null);
      setNotice(`Appareil lié à ${installed.canonicalAddress}.`);
      router.push("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Installation du certificat impossible.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="qn-onboarding qn-devices-page">
      <section className="qn-card qn-devices-card">
        <div className="qn-vault-head">
          <div>
            <div className="qn-mark">Q</div>
            <p className="qn-kicker">QUANTIC MULTI-DEVICE</p>
            <h1>Une identité. Plusieurs appareils. Des clés séparées.</h1>
            <p className="qn-lead">La clé maîtresse autorise les appareils, mais elle n’est jamais copiée sur les appareils secondaires. Chaque appareil reçoit sa propre clé de chiffrement.</p>
          </div>
          <Link className="qn-back-link" href="/">← QuanticMail</Link>
        </div>

        {identity ? (
          <div className="qn-vault-grid">
            <section className="qn-vault-section">
              <p className="qn-kicker">CET APPAREIL</p>
              <h2>{identity.deviceLabel ?? "Appareil Quantic"}</h2>
              <code className="qn-vault-address">{identity.deviceId ?? "migration en cours"}</code>
              <p className="qn-footnote">{identity.role === "secondary" ? "Appareil secondaire certifié." : "Appareil maître : il peut signer l’autorisation de nouveaux appareils."}</p>

              <div className="qn-device-list">
                <strong>Appareils visibles sur le relais</strong>
                {devices.length === 0 ? <p className="qn-footnote">Aucun registre distant disponible pour le moment.</p> : devices.map((device) => (
                  <div className="qn-device-row" key={device.deviceId}>
                    <div><b>{device.label}</b><small>{device.kind === "root" ? "maître" : "lié"}</small></div>
                    <code>{device.deviceId}</code>
                  </div>
                ))}
              </div>
            </section>

            <section className="qn-vault-section">
              <p className="qn-kicker">AUTORISER</p>
              <h2>Signer un nouvel appareil</h2>
              {identity.role === "secondary" || !identity.signingPrivateKey ? (
                <p className="qn-footnote">Cet appareil n’a pas la clé maîtresse. Il peut envoyer et recevoir des messages, mais pas autoriser d’autres appareils.</p>
              ) : (
                <form className="qn-vault-form" onSubmit={approveDevice}>
                  <label htmlFor="device-request">Demande créée sur le nouvel appareil</label>
                  <input id="device-request" type="file" accept=".quantic-device-request,application/json" onChange={(e) => setRequestFile(e.target.files?.[0] ?? null)} required />
                  <button disabled={busy}>{busy ? "Signature…" : "Signer le certificat"}</button>
                </form>
              )}
            </section>
          </div>
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
              <p className="qn-footnote">Sur l’appareil maître, ouvre cette même page, charge le fichier de demande et récupère le certificat signé. Reviens ensuite ici.</p>
              <form className="qn-vault-form" onSubmit={installCertificate}>
                <label htmlFor="device-certificate">Certificat signé</label>
                <input id="device-certificate" type="file" accept=".quantic-device-cert,application/json" onChange={(e) => setCertificateFile(e.target.files?.[0] ?? null)} required />
                <button disabled={busy || !pending}>{busy ? "Installation…" : "Lier cet appareil"}</button>
              </form>
            </section>
          </div>
        )}

        {(error || notice) && <p className={error ? "qn-error" : "qn-notice"}>{error || notice}</p>}
        <div className="qn-vault-warning">
          <strong>Principe de sécurité</strong>
          <p>Le fichier de demande ne contient que des clés publiques. Le certificat final est signé par la clé maîtresse. La clé maîtresse privée ne quitte jamais l’appareil qui autorise.</p>
        </div>
      </section>
    </main>
  );
}
