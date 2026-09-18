"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";

function QuanticGlobalNav() {
  return (
    <header className="qn-global-nav" aria-label="Navigation Quantic">
      <a className="qn-global-brand" href="/">
        <span className="qn-global-mark" aria-hidden="true" />
        <span>QUANTIC</span>
      </a>
      <nav className="qn-global-links">
        <a href="/vision/">Vision</a>
        <a className="active" href="/mail/" aria-current="page">Mail</a>
        <a href="/network/">Network</a>
        <a href="/products/">Produits</a>
        <a className="centre" href="/quantic/">Centre</a>
      </nav>
    </header>
  );
}
import {
  decryptEnvelope,
  encryptForRecipient,
  fingerprintPublicKey,
  fingerprintPublicKeyStrong,
  generateIdentityKeys,
  generateSigningKeys,
  randomToken,
  signChallenge,
} from "@/lib/quantic/crypto";
import { deviceIdFromPublicKey } from "@/lib/quantic/device";
import { selectEnvelopePrivateKey } from "@/lib/quantic/envelope-core.mjs";
import { createInitialManifest, verifyManifestBrowser } from "@/lib/quantic/manifest";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";
import { localMessageFromEnvelope } from "@/lib/quantic/message-core.mjs";
import { shouldBootstrapRootManifest, shouldUseStaticFallbackForPreKeyError } from "@/lib/quantic/recovery-policy.mjs";
import { generateOneTimePreKey, publicPreKey, verifyPreKeySignature, type SignedPreKeyRecord } from "@/lib/quantic/prekey";
import {
  deleteLocalPreKey,
  deleteOutboxItem,
  getLocalContact,
  getLocalIdentity,
  getLocalPreKey,
  listLocalMessages,
  listOutboxItems,
  saveLocalContact,
  saveLocalIdentity,
  saveLocalMessage,
  saveLocalPreKeys,
  saveOutboxItem,
  type LocalContactDevice,
  type LocalIdentity,
  type LocalMessage,
  type LocalOutboxItem,
} from "@/lib/quantic/local-db";

type RelayEnvelope = {
  id: string;
  clientMessageId: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  ciphertext: string;
  iv: string;
  ephemeralPublicKey: JsonWebKey;
  createdAt: string;
};

type DeliveryReceipt = {
  id: string;
  clientMessageId: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  deliveredAt: string;
};

type PlainPayload = {
  id: string;
  from: string;
  to: string;
  subject: string;
  body: string;
  createdAt: string;
  syncCopy?: boolean;
};

type ResolvedDevice = LocalContactDevice & { kind: "root" | "linked" };

type ResolvedIdentity = {
  address: string;
  canonicalAddress: string;
  fingerprint: string;
  publicKey: JsonWebKey;
  signingPublicKey?: JsonWebKey;
  rootDeviceId?: string;
  deviceId?: string;
  devices: ResolvedDevice[];
  manifest?: QuanticIdentityManifest | null;
};

type RegisterResult = ResolvedIdentity;

type DeliveryKey = {
  publicKey: JsonWebKey;
  keyMode: "one-time-prekey" | "static-fallback";
  preKeyId?: string;
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

function normalizeLocator(value: string) {
  return value.trim().toLowerCase().replace(/@quantic$/i, "");
}

function samePublicKey(a: JsonWebKey, b: JsonWebKey) {
  return a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;
}

function preKeyIdFromEnvelope(envelope: RelayEnvelope) {
  const kid = envelope.ephemeralPublicKey.kid;
  if (typeof kid !== "string") return null;
  const match = /^quantic-prekey:([0-9a-f]{32})$/.exec(kid);
  return match?.[1] ?? null;
}

async function ensureLocalIdentity(local: LocalIdentity): Promise<LocalIdentity> {
  if (local.role === "secondary" || local.deviceCertificate) {
    if (!local.canonicalAddress || !local.signingPublicKey || !local.deviceCertificate) {
      throw new Error("Certificat multi-appareil incomplet.");
    }
    const deviceId = local.deviceId ?? (await deviceIdFromPublicKey(local.publicKey));
    const next: LocalIdentity = {
      ...local,
      deviceId,
      deviceLabel: local.deviceLabel ?? local.deviceCertificate.payload.deviceLabel,
      role: "secondary",
    };
    await saveLocalIdentity(next);
    return next;
  }

  let signingPublicKey = local.signingPublicKey;
  let signingPrivateKey = local.signingPrivateKey;
  if (!signingPublicKey || !signingPrivateKey) {
    const signing = await generateSigningKeys();
    signingPublicKey = signing.signingPublicKey;
    signingPrivateKey = signing.signingPrivateKey;
  }

  const legacyFingerprint = await fingerprintPublicKey(signingPublicKey);
  const strongFingerprint = await fingerprintPublicKeyStrong(signingPublicKey);
  const canonicalStoredFingerprint = local.canonicalAddress?.match(/~([0-9a-f]{10}|[0-9a-f]{32})@quantic$/)?.[1];
  const storedFingerprint = local.fingerprint ?? canonicalStoredFingerprint;
  const fingerprint = storedFingerprint ?? strongFingerprint;
  const expectedFingerprint = fingerprint.length === 32 ? strongFingerprint : legacyFingerprint;
  if (fingerprint !== expectedFingerprint) throw new Error("L’empreinte locale ne correspond plus à la clé de propriété Quantic.");
  const expectedCanonical = `${local.handle}~${fingerprint}@quantic`;
  if (local.canonicalAddress && local.canonicalAddress !== expectedCanonical) {
    throw new Error("L’adresse canonique locale est incohérente avec la clé de propriété.");
  }

  const manifestRootDeviceId = local.manifest?.payload.devices.find((device) => device.kind === "root")?.deviceId;
  const deviceId = local.deviceId ?? manifestRootDeviceId ?? (await deviceIdFromPublicKey(local.publicKey));
  const next: LocalIdentity = {
    ...local,
    address: `${local.handle}@quantic`,
    canonicalAddress: expectedCanonical,
    fingerprint,
    signingPublicKey,
    signingPrivateKey,
    deviceId,
    deviceLabel: local.deviceLabel ?? "Appareil principal",
    deviceSigningPublicKey: local.deviceSigningPublicKey ?? signingPublicKey,
    deviceSigningPrivateKey: local.deviceSigningPrivateKey ?? signingPrivateKey,
    role: "root",
  };
  await saveLocalIdentity(next);
  return next;
}

export function QuanticNetworkV11App() {
  const [identity, setIdentity] = useState<LocalIdentity | null>(null);
  const [messages, setMessages] = useState<LocalMessage[]>([]);
  const [outboxCount, setOutboxCount] = useState(0);
  const [handle, setHandle] = useState("");
  const [to, setTo] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [scope, setScope] = useState<"all" | "in" | "out">("all");
  const [busy, setBusy] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const syncingRef = useRef(false);

  const refreshLocal = useCallback(async () => {
    const [localMessages, outbox] = await Promise.all([listLocalMessages(), listOutboxItems()]);
    setMessages(localMessages);
    setOutboxCount(outbox.length);
  }, []);

  const publishManifest = useCallback(async (local: LocalIdentity, manifest: QuanticIdentityManifest) => {
    const result = await fetchJson<{ manifest: QuanticIdentityManifest }>("/api/quantic/manifest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ manifest }),
    });
    const next = { ...local, manifest: result.manifest };
    await saveLocalIdentity(next);
    setIdentity(next);
    return next;
  }, []);

  const publishIdentity = useCallback(async (local: LocalIdentity): Promise<RegisterResult> => {
    if (local.role === "secondary") {
      if (!local.deviceCertificate) throw new Error("Certificat d’appareil secondaire absent.");
      return fetchJson<RegisterResult>("/api/quantic/devices/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ certificate: local.deviceCertificate, authToken: local.authToken }),
      });
    }

    if (!local.signingPublicKey || !local.signingPrivateKey) throw new Error("Clé de propriété Quantic absente.");
    const locator = local.canonicalAddress ?? local.handle;
    const base = {
      handle: locator,
      publicKey: local.publicKey,
      signingPublicKey: local.signingPublicKey,
      authToken: local.authToken,
    };
    try {
      return await fetchJson<RegisterResult>("/api/quantic/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(base),
      });
    } catch (err) {
      if (!(err instanceof HttpError) || err.status !== 428) throw err;
    }

    const proof = await fetchJson<{ challenge: string }>("/api/quantic/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle: locator, publicKey: local.publicKey, signingPublicKey: local.signingPublicKey }),
    });
    const signature = await signChallenge(local.signingPrivateKey, proof.challenge);
    return fetchJson<RegisterResult>("/api/quantic/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...base, challenge: proof.challenge, signature }),
    });
  }, []);

  const syncOwnManifest = useCallback(async (local: LocalIdentity) => {
    if (!local.canonicalAddress) return local;
    if (local.manifest) {
      if (!(await verifyManifestBrowser(local.manifest))) throw new Error("Le manifeste local de cette identité a une signature invalide.");
      return publishManifest(local, local.manifest);
    }
    try {
      const result = await fetchJson<{ manifest: QuanticIdentityManifest }>(
        `/api/quantic/manifest?handle=${encodeURIComponent(local.canonicalAddress)}`,
      );
      if (!(await verifyManifestBrowser(result.manifest))) throw new Error("Le manifeste Quantic distant a une signature invalide.");
      if (result.manifest.payload.canonicalAddress !== local.canonicalAddress) throw new Error("Le manifeste distant vise une autre identité.");
      const next = { ...local, manifest: result.manifest };
      await saveLocalIdentity(next);
      setIdentity(next);
      return next;
    } catch (err) {
      if (err instanceof HttpError && shouldBootstrapRootManifest(local.role, err.status)) {
        if (!local.signingPrivateKey || !local.signingPublicKey || !local.deviceSigningPrivateKey || !local.deviceSigningPublicKey || !local.deviceId) {
          throw new Error("Impossible de reconstruire le manifeste racine Quantic : clés locales incomplètes.");
        }
        const manifest = await createInitialManifest(local);
        return publishManifest(local, manifest);
      }
      if (err instanceof HttpError && err.status === 404) return local;
      throw err;
    }
  }, [publishManifest]);

  const ensurePreKeyPool = useCallback(async (local: LocalIdentity) => {
    if (!local.canonicalAddress || !local.deviceId || !local.deviceSigningPrivateKey || !local.manifest) return;
    const status = await fetchJson<{ available: number }>(
      `/api/quantic/prekeys/status?handle=${encodeURIComponent(local.canonicalAddress)}&deviceId=${encodeURIComponent(local.deviceId)}`,
      { headers: { authorization: `Bearer ${local.authToken}` } },
    );
    if (status.available >= 12) return;
    const count = Math.min(32, Math.max(1, 32 - status.available));
    const generated = await Promise.all(Array.from({ length: count }, () => generateOneTimePreKey(local)));
    await saveLocalPreKeys(generated);
    await fetchJson("/api/quantic/prekeys/publish", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${local.authToken}` },
      body: JSON.stringify({
        handle: local.canonicalAddress,
        deviceId: local.deviceId,
        records: generated.map(publicPreKey),
      }),
    });
  }, []);

  const pushOutboxItem = useCallback(async (local: LocalIdentity, item: LocalOutboxItem) => {
    if (!local.deviceId || !item.recipientDeviceId) throw new Error("Routage multi-appareil incomplet.");
    await fetchJson("/api/quantic/send", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${local.authToken}` },
      body: JSON.stringify({
        clientMessageId: item.id,
        from: item.from,
        fromDeviceId: local.deviceId,
        to: item.to,
        toDeviceId: item.recipientDeviceId,
        ciphertext: item.ciphertext,
        iv: item.iv,
        ephemeralPublicKey: item.ephemeralPublicKey,
      }),
    });
    await saveOutboxItem({ ...item, lastAttemptAt: new Date().toISOString() });
  }, []);

  const flushOutbox = useCallback(async (local: LocalIdentity) => {
    const items = await listOutboxItems();
    const retryCutoff = Date.now() - 30_000;
    for (const item of items) {
      if (item.lastAttemptAt && Date.parse(item.lastAttemptAt) > retryCutoff) continue;
      try {
        await pushOutboxItem(local, item);
      } catch {
        // The encrypted delivery remains local and is retried without claiming a second prekey.
      }
    }
  }, [pushOutboxItem]);

  const resolveRecipient = useCallback(async (locator: string): Promise<ResolvedIdentity> => {
    const cached = await getLocalContact(locator);
    let remote: ResolvedIdentity;
    try {
      remote = await fetchJson<ResolvedIdentity>(`/api/quantic/resolve?handle=${encodeURIComponent(locator)}`);
    } catch (err) {
      if (!cached) throw err;
      const devices = cached.devices?.length
        ? cached.devices.map((device) => ({ ...device, kind: device.kind ?? "linked" as const }))
        : [{ deviceId: await deviceIdFromPublicKey(cached.publicKey), label: "Appareil principal", publicKey: cached.publicKey, kind: "root" as const }];
      return {
        address: cached.address,
        canonicalAddress: cached.canonicalAddress ?? cached.address,
        fingerprint: cached.fingerprint ?? "",
        publicKey: cached.publicKey,
        signingPublicKey: cached.signingPublicKey,
        devices,
      };
    }

    if (cached && !samePublicKey(cached.publicKey, remote.publicKey)) {
      throw new Error(`Alerte sécurité : la clé racine de ${remote.address} a changé. Utilisez son adresse canonique pour vérifier son identité.`);
    }

    if (remote.manifest) {
      if (!(await verifyManifestBrowser(remote.manifest))) throw new Error(`Manifeste V1.1 invalide pour ${remote.canonicalAddress}.`);
      if (remote.manifest.payload.canonicalAddress !== remote.canonicalAddress) throw new Error("Le manifeste et l’identité résolue ne correspondent pas.");
      if (cached?.signingPublicKey && !samePublicKey(cached.signingPublicKey, remote.manifest.payload.identitySigningPublicKey)) {
        throw new Error("Alerte sécurité : la clé maîtresse du contact a changé.");
      }
      if (cached?.manifestSequence && remote.manifest.payload.sequence < cached.manifestSequence) {
        throw new Error(`Rollback V1.1 bloqué : manifeste #${remote.manifest.payload.sequence} plus ancien que #${cached.manifestSequence}.`);
      }
      remote.publicKey = remote.manifest.payload.identityPublicKey;
      remote.signingPublicKey = remote.manifest.payload.identitySigningPublicKey;
      remote.devices = remote.manifest.payload.devices.map((device) => ({
        deviceId: device.deviceId,
        label: device.label,
        publicKey: device.publicKey,
        deviceSigningPublicKey: device.deviceSigningPublicKey,
        kind: device.kind,
      }));
    } else if (cached?.manifestSequence) {
      throw new Error("Downgrade V1.1 bloqué : le serveur ne fournit plus le manifeste signé connu pour ce contact.");
    }

    if (!remote.devices?.length) {
      remote.devices = [{ deviceId: await deviceIdFromPublicKey(remote.publicKey), label: "Appareil principal", publicKey: remote.publicKey, kind: "root" }];
    }

    const now = new Date().toISOString();
    await saveLocalContact({
      handle: locator,
      address: remote.address,
      canonicalAddress: remote.canonicalAddress,
      fingerprint: remote.fingerprint,
      publicKey: remote.publicKey,
      signingPublicKey: remote.manifest?.payload.identitySigningPublicKey ?? remote.signingPublicKey ?? cached?.signingPublicKey,
      manifestSequence: remote.manifest?.payload.sequence ?? cached?.manifestSequence,
      devices: remote.devices,
      firstSeenAt: cached?.firstSeenAt ?? now,
      lastSeenAt: now,
    });
    return remote;
  }, []);

  const claimDeliveryKey = useCallback(async (
    local: LocalIdentity,
    recipientCanonicalAddress: string,
    device: ResolvedDevice,
  ): Promise<DeliveryKey> => {
    if (!local.canonicalAddress || !local.deviceId || !device.deviceSigningPublicKey) {
      return { publicKey: device.publicKey, keyMode: "static-fallback" };
    }
    try {
      const response = await fetchJson<{ prekey: SignedPreKeyRecord }>("/api/quantic/prekeys/claim", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${local.authToken}` },
        body: JSON.stringify({
          from: local.canonicalAddress,
          fromDeviceId: local.deviceId,
          to: recipientCanonicalAddress,
          toDeviceId: device.deviceId,
        }),
      });
      if (!(await verifyPreKeySignature(response.prekey, device.deviceSigningPublicKey))) {
        throw new Error(`Signature de one-time prekey invalide pour ${device.label}.`);
      }
      return { publicKey: response.prekey.publicKey, keyMode: "one-time-prekey", preKeyId: response.prekey.preKeyId };
    } catch (err) {
      if (err instanceof HttpError && shouldUseStaticFallbackForPreKeyError(err.status, err.message)) {
        return { publicKey: device.publicKey, keyMode: "static-fallback" };
      }
      throw err;
    }
  }, []);

  const queueDelivery = useCallback(async (input: {
    local: LocalIdentity;
    logicalMessageId: string;
    transportTo: string;
    logicalTo: string;
    device: ResolvedDevice;
    subject: string;
    body: string;
    createdAt: string;
    syncCopy: boolean;
  }) => {
    const senderCanonical = input.local.canonicalAddress ?? input.local.address;
    const deliveryId = crypto.randomUUID();
    const key = await claimDeliveryKey(input.local, input.transportTo, input.device);
    const payload: PlainPayload = {
      id: input.logicalMessageId,
      from: senderCanonical,
      to: input.logicalTo,
      subject: input.subject,
      body: input.body,
      createdAt: input.createdAt,
      syncCopy: input.syncCopy || undefined,
    };
    const encrypted = await encryptForRecipient(key.publicKey, payload);
    const ephemeralPublicKey = key.preKeyId
      ? { ...encrypted.ephemeralPublicKey, kid: `quantic-prekey:${key.preKeyId}` }
      : encrypted.ephemeralPublicKey;
    const outboxItem: LocalOutboxItem = {
      id: deliveryId,
      from: senderCanonical,
      to: input.transportTo,
      recipientDeviceId: input.device.deviceId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      ephemeralPublicKey,
      keyMode: key.keyMode,
      preKeyId: key.preKeyId,
      logicalMessageId: input.logicalMessageId,
      syncCopy: input.syncCopy,
      createdAt: input.createdAt,
    };
    await saveOutboxItem(outboxItem);
    try {
      await pushOutboxItem(input.local, outboxItem);
      return true;
    } catch {
      return false;
    }
  }, [claimDeliveryKey, pushOutboxItem]);

  const sync = useCallback(async (local = identity, quiet = false) => {
    if (!local || syncingRef.current) return;
    syncingRef.current = true;
    setSyncing(true);
    if (!quiet) {
      setError("");
      setNotice("Synchronisation…");
    }
    try {
      let active = await ensureLocalIdentity(local);
      if (active !== local) setIdentity(active);
      if (!active.canonicalAddress || !active.deviceId) throw new Error("Identité multi-appareil incomplète.");

      const registration = await publishIdentity(active);
      if (active.role !== "secondary" && registration.rootDeviceId && registration.rootDeviceId !== active.deviceId) {
        const manifestRootDeviceId = active.manifest?.payload.devices.find((device) => device.kind === "root")?.deviceId;
        if (manifestRootDeviceId && manifestRootDeviceId !== registration.rootDeviceId) {
          throw new Error("Conflit entre le manifeste local et l’appareil racine enregistré.");
        }
        active = { ...active, deviceId: registration.rootDeviceId };
        await saveLocalIdentity(active);
        setIdentity(active);
      }
      active = await syncOwnManifest(active);
      if (!active.canonicalAddress || !active.deviceId) throw new Error("Identité V1.1 incomplète après synchronisation.");
      await ensurePreKeyPool(active);
      await flushOutbox(active);
      const locator = active.canonicalAddress;
      const deviceParam = encodeURIComponent(active.deviceId);

      const pulled = await fetchJson<{ envelopes: RelayEnvelope[] }>(
        `/api/quantic/pull?handle=${encodeURIComponent(locator)}&deviceId=${deviceParam}`,
        { headers: { authorization: `Bearer ${active.authToken}` } },
      );
      const acknowledged: string[] = [];
      for (const envelope of pulled.envelopes) {
        try {
          if (envelope.toDeviceId !== active.deviceId) throw new Error("Enveloppe destinée à un autre appareil.");
          const preKeyId = preKeyIdFromEnvelope(envelope);
          const localPreKey = preKeyId ? await getLocalPreKey(preKeyId) : null;
          const selected = selectEnvelopePrivateKey(
            { keyMode: preKeyId ? "one-time-prekey" : "static-fallback", preKeyId: preKeyId ?? undefined },
            active.privateKey,
            localPreKey,
          );
          const payload = await decryptEnvelope<PlainPayload>(selected.privateKey, envelope);
          const localMessage = localMessageFromEnvelope(payload, envelope) as LocalMessage;
          await saveLocalMessage(localMessage);
          if (selected.consumePreKeyId) await deleteLocalPreKey(selected.consumePreKeyId);
          acknowledged.push(envelope.id);
        } catch {
          // Keep undecryptable, consumed-prekey or misrouted envelopes on the relay.
        }
      }

      if (acknowledged.length) {
        await fetchJson("/api/quantic/ack", {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${active.authToken}` },
          body: JSON.stringify({ handle: locator, deviceId: active.deviceId, ids: acknowledged }),
        });
      }

      const receiptPayload = await fetchJson<{ receipts: DeliveryReceipt[] }>(
        `/api/quantic/receipts?handle=${encodeURIComponent(locator)}&deviceId=${deviceParam}`,
        { headers: { authorization: `Bearer ${active.authToken}` } },
      );
      const receiptIds: string[] = [];
      for (const receipt of receiptPayload.receipts) {
        await deleteOutboxItem(receipt.clientMessageId);
        receiptIds.push(receipt.id);
      }
      if (receiptIds.length) {
        await fetchJson("/api/quantic/receipts", {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${active.authToken}` },
          body: JSON.stringify({ handle: locator, deviceId: active.deviceId, ids: receiptIds }),
        });
      }

      await refreshLocal();
      if (!quiet) {
        const parts: string[] = [];
        if (acknowledged.length) parts.push(`${acknowledged.length} reçu(s)/synchronisé(s)`);
        if (receiptIds.length) parts.push(`${receiptIds.length} livré(s)`);
        if (active.manifest) parts.push(`V1.1 #${active.manifest.payload.sequence}`);
        setNotice(parts.length ? `${parts.join(" · ")}.` : "À jour.");
      }
    } catch (err) {
      if (!quiet) setError(err instanceof Error ? err.message : "Synchronisation impossible.");
    } finally {
      syncingRef.current = false;
      setSyncing(false);
    }
  }, [ensurePreKeyPool, flushOutbox, identity, publishIdentity, refreshLocal, syncOwnManifest]);

  useEffect(() => {
    void (async () => {
      try {
        const stored = await getLocalIdentity();
        let active = stored ? await ensureLocalIdentity(stored) : null;
        setIdentity(active);
        await refreshLocal();
        if (active) {
          const registration = await publishIdentity(active);
          if (active.role !== "secondary" && registration.rootDeviceId && registration.rootDeviceId !== active.deviceId) {
            const manifestRootDeviceId = active.manifest?.payload.devices.find((device) => device.kind === "root")?.deviceId;
            if (manifestRootDeviceId && manifestRootDeviceId !== registration.rootDeviceId) {
              throw new Error("Conflit entre le manifeste local et l’appareil racine enregistré.");
            }
            active = { ...active, deviceId: registration.rootDeviceId };
            await saveLocalIdentity(active);
            setIdentity(active);
          }
          active = await syncOwnManifest(active);
          await ensurePreKeyPool(active);
          setIdentity(active);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Impossible d’ouvrir le stockage local QuanticMail.");
      }
    })();
  }, [ensurePreKeyPool, publishIdentity, refreshLocal, syncOwnManifest]);

  useEffect(() => {
    if (!identity) return;
    const initialSync = window.setTimeout(() => void sync(identity, true), 0);
    const timer = window.setInterval(() => void sync(identity, true), 12_000);
    return () => {
      window.clearTimeout(initialSync);
      window.clearInterval(timer);
    };
  }, [identity, sync]);

  async function createIdentity(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const clean = normalizeLocator(handle);
      if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(clean)) throw new Error("Choisissez 3 à 32 caractères : lettres, chiffres, point, tiret ou underscore.");
      const keys = await generateIdentityKeys();
      const fingerprint = await fingerprintPublicKeyStrong(keys.signingPublicKey);
      let local: LocalIdentity = {
        handle: clean,
        address: `${clean}@quantic`,
        canonicalAddress: `${clean}~${fingerprint}@quantic`,
        fingerprint,
        publicKey: keys.publicKey,
        privateKey: keys.privateKey,
        signingPublicKey: keys.signingPublicKey,
        signingPrivateKey: keys.signingPrivateKey,
        deviceId: await deviceIdFromPublicKey(keys.publicKey),
        deviceLabel: "Appareil principal",
        deviceSigningPublicKey: keys.signingPublicKey,
        deviceSigningPrivateKey: keys.signingPrivateKey,
        role: "root",
        authToken: randomToken(),
        createdAt: new Date().toISOString(),
      };
      await publishIdentity(local);
      const manifest = await createInitialManifest(local);
      local = await publishManifest(local, manifest);
      await saveLocalIdentity(local);
      await ensurePreKeyPool(local);
      setIdentity(local);
      setNotice(`${local.address} est actif en V1.1. Identité canonique forte : ${local.canonicalAddress}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Création impossible.");
    } finally {
      setBusy(false);
    }
  }

  async function sendMessage(event: FormEvent) {
    event.preventDefault();
    if (!identity) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      let active = await ensureLocalIdentity(identity);
      active = await syncOwnManifest(active);
      setIdentity(active);
      const recipient = normalizeLocator(to);
      const resolved = await resolveRecipient(recipient);
      const senderCanonical = active.canonicalAddress ?? active.address;
      const createdAt = new Date().toISOString();
      const finalSubject = subject.trim() || "Sans objet";
      const logicalMessageId = crypto.randomUUID();

      await saveLocalMessage({
        id: logicalMessageId,
        direction: "out",
        from: senderCanonical,
        to: resolved.canonicalAddress,
        subject: finalSubject,
        body,
        createdAt,
      });

      let normalSubmitted = 0;
      for (const device of resolved.devices) {
        if (await queueDelivery({
          local: active,
          logicalMessageId,
          transportTo: resolved.canonicalAddress,
          logicalTo: resolved.canonicalAddress,
          device,
          subject: finalSubject,
          body,
          createdAt,
          syncCopy: false,
        })) normalSubmitted += 1;
      }

      let syncSubmitted = 0;
      const ownDevices: ResolvedDevice[] = active.manifest?.payload.devices
        .filter((device) => device.deviceId !== active.deviceId)
        .map((device) => ({
          deviceId: device.deviceId,
          label: device.label,
          publicKey: device.publicKey,
          deviceSigningPublicKey: device.deviceSigningPublicKey,
          kind: device.kind,
        })) ?? [];
      for (const device of ownDevices) {
        if (await queueDelivery({
          local: active,
          logicalMessageId,
          transportTo: senderCanonical,
          logicalTo: resolved.canonicalAddress,
          device,
          subject: finalSubject,
          body,
          createdAt,
          syncCopy: true,
        })) syncSubmitted += 1;
      }

      const normalText = `${normalSubmitted}/${resolved.devices.length} livraison(s)`;
      const syncText = ownDevices.length ? ` · ${syncSubmitted}/${ownDevices.length} copie(s) historique` : "";
      setNotice(`${normalText}${syncText} pour ${resolved.address}.`);
      setTo("");
      setSubject("");
      setBody("");
      await refreshLocal();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Envoi impossible.");
    } finally {
      setBusy(false);
    }
  }

  const visibleMessages = useMemo(
    () => messages.filter((message) => scope === "all" || message.direction === scope),
    [messages, scope],
  );

  if (!identity) {
    return (
      <>
        <QuanticGlobalNav />
        <main className="qn-onboarding">
        <section className="qn-card qn-onboarding-card">
          <div className="qn-mark">Q</div>
          <p className="qn-kicker">QUANTIC SILLAGE</p>
          <h1>Crée ton identité Quantic.</h1>
          <p className="qn-lead">Un nom humain, une identité cryptographique forte, un manifeste signé et des clés de message à usage unique.</p>
          <form onSubmit={createIdentity} className="qn-create-form">
            <label htmlFor="handle">Ton adresse</label>
            <div className="qn-address-input">
              <input id="handle" value={handle} onChange={(e) => setHandle(e.target.value)} placeholder="sansa" autoComplete="off" />
              <span>@quantic</span>
            </div>
            <button disabled={busy}>{busy ? "Création…" : "Créer mon identité V1.1"}</button>
          </form>
          <Link className="qn-secondary-link" href="/devices">Lier cet appareil par QR</Link>
          {error && <p className="qn-error">{error}</p>}
          <p className="qn-footnote">V1.1 · identité 128 bits pour les nouveaux comptes · pairing QR · one-time prekeys · historique multi-appareil.</p>
        </section>
      </main>
      </>
    );
  }

  return (
    <>
      <QuanticGlobalNav />
      <main className="qn-app">
      <header className="qn-topbar">
        <div className="qn-brand"><span className="qn-mark small">Q</span><div><strong>QuanticMail</strong><small>Quantic Network · V1.1 secure sync</small></div></div>
        <div className="qn-identity">
          <button className="qn-address" onClick={() => void navigator.clipboard.writeText(identity.address)} title="Copier le nom Quantic">{identity.address}</button>
          {identity.canonicalAddress && <button className="qn-address" onClick={() => void navigator.clipboard.writeText(identity.canonicalAddress!)} title="Copier l’identité canonique">{identity.canonicalAddress}</button>}
          <button className="qn-sync" onClick={() => void sync()} disabled={syncing}>{syncing ? "Synchro…" : "Synchroniser"}</button>
        </div>
      </header>

      <div className="qn-grid">
        <aside className="qn-sidebar qn-card">
          <p className="qn-kicker">BOÎTE LOCALE</p>
          <button className={scope === "all" ? "active" : ""} onClick={() => setScope("all")}>Tous <span>{messages.length}</span></button>
          <button className={scope === "in" ? "active" : ""} onClick={() => setScope("in")}>Reçus <span>{messages.filter((m) => m.direction === "in").length}</span></button>
          <button className={scope === "out" ? "active" : ""} onClick={() => setScope("out")}>Envoyés <span>{messages.filter((m) => m.direction === "out").length}</span></button>
          <div className="qn-local-note">
            <strong>{identity.role === "secondary" ? "Appareil lié" : "Appareil maître"}</strong>
            <p>{identity.deviceLabel ?? identity.deviceId}</p>
            <p>{identity.deviceId}</p>
            <p>{identity.manifest ? `Manifeste V1.1 #${identity.manifest.payload.sequence}` : "Manifeste en attente"}</p>
            <p>{outboxCount ? `${outboxCount} livraison(s) chiffrée(s) en attente.` : "Aucune livraison en attente."}</p>
            <Link className="qn-secondary-link" href="/devices">Gérer les appareils</Link>
          </div>
        </aside>

        <section className="qn-card qn-inbox">
          <div className="qn-section-head"><div><p className="qn-kicker">MESSAGES</p><h2>{scope === "in" ? "Reçus" : scope === "out" ? "Envoyés" : "Tous les messages"}</h2></div><span>{visibleMessages.length}</span></div>
          <div className="qn-message-list">
            {visibleMessages.length === 0 ? <div className="qn-empty">Aucun message local pour le moment.</div> : visibleMessages.map((message) => (
              <article key={message.id} className="qn-message">
                <div className="qn-message-meta"><span className={`qn-direction ${message.direction}`}>{message.direction === "in" ? "REÇU" : "ENVOYÉ"}</span><time>{new Date(message.createdAt).toLocaleString("fr-FR")}</time></div>
                <h3>{message.subject}</h3>
                <p className="qn-correspondent">{message.direction === "in" ? `De ${message.from}` : `À ${message.to}`}</p>
                <p className="qn-body">{message.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="qn-card qn-compose">
          <p className="qn-kicker">NOUVEAU</p>
          <h2>Message Quantic</h2>
          <form onSubmit={sendMessage}>
            <label>À</label>
            <div className="qn-address-input compact"><input value={to} onChange={(e) => setTo(e.target.value)} placeholder="marie ou marie~empreinte" required /><span>@quantic</span></div>
            <label>Objet</label>
            <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Sans objet" />
            <label>Message</label>
            <textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="Écrire…" rows={12} required />
            <button disabled={busy}>{busy ? "Vérification et chiffrement…" : "Vérifier, chiffrer et envoyer"}</button>
          </form>
          {(error || notice) && <p className={error ? "qn-error" : "qn-notice"}>{error || notice}</p>}
          <p className="qn-footnote">V1.1 vérifie le manifeste signé, réclame une one-time prekey quand elle existe et synchronise les messages envoyés vers tes autres appareils autorisés.</p>
        </section>
      </div>
    </main>
  );
}
