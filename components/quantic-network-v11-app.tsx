"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";

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

type MailIconName =
  | "menu" | "search" | "sync" | "inbox" | "send" | "devices" | "vault"
  | "network" | "compose" | "close" | "back" | "mail" | "chevron" | "copy";

function MailIcon({ name, className = "" }: { name: MailIconName; className?: string }) {
  const common = { width: 24, height: 24, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, className };
  if (name === "menu") return <svg {...common}><path d="M4 7h16M4 12h16M4 17h16" /></svg>;
  if (name === "search") return <svg {...common}><circle cx="10.8" cy="10.8" r="6.2" /><path d="m15.5 15.5 4.5 4.5" /></svg>;
  if (name === "sync") return <svg {...common}><path d="M20 7h-5V2" /><path d="M20 7a8 8 0 1 0 1 8" /></svg>;
  if (name === "inbox") return <svg {...common}><path d="M4 5h16l-1.5 14h-13L4 5Z" /><path d="M5 13h4l1.5 2h3L15 13h4" /></svg>;
  if (name === "send") return <svg {...common}><path d="m3.5 4.5 17 7.5-17 7.5 3.2-7.5-3.2-7.5Z" /><path d="M6.7 12h8.8" /></svg>;
  if (name === "devices") return <svg {...common}><rect x="7" y="2.5" width="10" height="19" rx="2" /><path d="M10 18.5h4" /></svg>;
  if (name === "vault") return <svg {...common}><rect x="4" y="5" width="16" height="14" rx="2" /><path d="M8 5V3h8v2M8 11h8" /></svg>;
  if (name === "network") return <svg {...common}><circle cx="12" cy="5" r="2.3" /><circle cx="5" cy="18" r="2.3" /><circle cx="19" cy="18" r="2.3" /><path d="m10.7 7-4.4 8.8M13.3 7l4.4 8.8M7.3 18h9.4" /></svg>;
  if (name === "compose") return <svg {...common}><path d="M13.5 5.5 18.5 10.5 8 21H3v-5L13.5 5.5Z" /><path d="m12 7 5 5M15.5 3.5l5 5" /></svg>;
  if (name === "close") return <svg {...common}><path d="m6 6 12 12M18 6 6 18" /></svg>;
  if (name === "back") return <svg {...common}><path d="m15 5-7 7 7 7" /></svg>;
  if (name === "mail") return <svg {...common}><rect x="3.5" y="5.5" width="17" height="13" rx="2" /><path d="m5 7 7 5 7-5" /></svg>;
  if (name === "copy") return <svg {...common}><rect x="8" y="8" width="11" height="11" rx="2" /><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" /></svg>;
  return <svg {...common}><path d="m9 6 6 6-6 6" /></svg>;
}

function mailDisplayName(address: string) {
  const raw = String(address || "").split("@")[0] || "Quantic";
  return raw.split("~")[0] || raw;
}

function mailInitial(address: string) {
  return mailDisplayName(address).slice(0, 1).toUpperCase() || "Q";
}

function formatMailDate(value: string) {
  const date = new Date(value);
  const now = new Date();
  if (date.toDateString() === now.toDateString()) {
    return date.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
  }
  const diffDays = Math.floor((now.getTime() - date.getTime()) / 86_400_000);
  if (diffDays < 6) return date.toLocaleDateString("fr-FR", { weekday: "short" }).replace(".", "");
  return date.toLocaleDateString("fr-FR", { day: "numeric", month: "short" });
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
  const [scope, setScope] = useState<"all" | "in" | "out">("in");
  const [busy, setBusy] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [composeOpen, setComposeOpen] = useState(false);
  const [selectedMessageId, setSelectedMessageId] = useState<string | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [focusTab, setFocusTab] = useState<"priority" | "other">("priority");
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
      setComposeOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Envoi impossible.");
    } finally {
      setBusy(false);
    }
  }

  const visibleMessages = useMemo(() => {
    const base = messages
      .filter((message) => scope === "all" || message.direction === scope)
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
    const query = searchQuery.trim().toLowerCase();
    return query
      ? base.filter((message) =>
          [message.subject, message.body, message.from, message.to].some((value) => String(value || "").toLowerCase().includes(query)),
        )
      : base;
  }, [messages, scope, searchQuery]);

  const focusedMessages = useMemo(() => {
    if (scope !== "in" || visibleMessages.length === 0) return visibleMessages;
    const newest = Date.parse(visibleMessages[0].createdAt);
    const cutoff = newest - 7 * 86_400_000;
    return focusTab === "priority"
      ? visibleMessages.filter((message) => Date.parse(message.createdAt) >= cutoff)
      : visibleMessages.filter((message) => Date.parse(message.createdAt) < cutoff);
  }, [visibleMessages, focusTab, scope]);

  const selectedMessage = useMemo(
    () => messages.find((message) => message.id === selectedMessageId) ?? null,
    [messages, selectedMessageId],
  );

  const receivedCount = messages.filter((message) => message.direction === "in").length;
  const sentCount = messages.filter((message) => message.direction === "out").length;

  if (!identity) {
    return (
      <main className="qn-onboarding">
        <section className="qn-card qn-onboarding-card">
          <div className="qn-mark">Q</div>
          <p className="qn-kicker">QUANTIC MAIL · V1.3</p>
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
    );
  }

  return (
    <main className="qn-mail-app">
      <header className="qm-header">
        <button className="qm-icon-btn qm-menu-btn" onClick={() => setDrawerOpen(true)} aria-label="Ouvrir les dossiers">
          <MailIcon name="menu" />
        </button>
        <div className="qm-header-title">
          <span className="qm-logo">Q</span>
          <div>
            <strong>{scope === "in" ? "Réception" : scope === "out" ? "Envoyés" : "Courrier"}</strong>
            <small>{identity.address}</small>
          </div>
        </div>
        <div className="qm-header-actions">
          <button className={"qm-icon-btn " + (syncing ? "is-spinning" : "")} onClick={() => void sync()} disabled={syncing} aria-label="Synchroniser">
            <MailIcon name="sync" />
          </button>
          <button className="qm-icon-btn" onClick={() => setSearchOpen((value) => !value)} aria-label="Rechercher">
            <MailIcon name="search" />
          </button>
        </div>
      </header>

      {searchOpen && (
        <div className="qm-searchbar">
          <MailIcon name="search" />
          <input value={searchQuery} onChange={(event) => setSearchQuery(event.target.value)} placeholder="Rechercher dans les messages" autoFocus />
          {searchQuery && <button onClick={() => setSearchQuery("")} aria-label="Effacer"><MailIcon name="close" /></button>}
        </div>
      )}

      {scope === "in" && (
        <div className="qm-focus-tabs" aria-label="Filtrer la réception">
          <button className={focusTab === "priority" ? "active" : ""} onClick={() => setFocusTab("priority")}>Prioritaires</button>
          <button className={focusTab === "other" ? "active" : ""} onClick={() => setFocusTab("other")}>Autres</button>
        </div>
      )}

      <div className="qm-shell">
        <aside className={"qm-drawer " + (drawerOpen ? "open" : "")}>
          <div className="qm-drawer-head">
            <div className="qm-drawer-brand">
              <span className="qm-logo large">Q</span>
              <div><strong>Quantic Mail</strong><small>{identity.address}</small></div>
            </div>
            <button className="qm-icon-btn qm-drawer-close" onClick={() => setDrawerOpen(false)} aria-label="Fermer"><MailIcon name="close" /></button>
          </div>

          <nav className="qm-folders">
            <p>Courrier</p>
            <button className={scope === "in" ? "active" : ""} onClick={() => { setScope("in"); setDrawerOpen(false); setSelectedMessageId(null); }}>
              <MailIcon name="inbox" /><span>Réception</span><b>{receivedCount}</b>
            </button>
            <button className={scope === "out" ? "active" : ""} onClick={() => { setScope("out"); setDrawerOpen(false); setSelectedMessageId(null); }}>
              <MailIcon name="send" /><span>Envoyés</span><b>{sentCount}</b>
            </button>
            <button className={scope === "all" ? "active" : ""} onClick={() => { setScope("all"); setDrawerOpen(false); setSelectedMessageId(null); }}>
              <MailIcon name="mail" /><span>Tous les messages</span><b>{messages.length}</b>
            </button>
          </nav>

          <div className="qm-drawer-separator" />

          <nav className="qm-folders qm-tools">
            <p>Quantic</p>
            <Link href="/devices" onClick={() => setDrawerOpen(false)}><MailIcon name="devices" /><span>Appareils</span><MailIcon name="chevron" /></Link>
            <Link href="/vault" onClick={() => setDrawerOpen(false)}><MailIcon name="vault" /><span>Identity Vault</span><MailIcon name="chevron" /></Link>
            <Link href="/network" onClick={() => setDrawerOpen(false)}><MailIcon name="network" /><span>Network</span><MailIcon name="chevron" /></Link>
          </nav>

          <div className="qm-drawer-identity">
            <strong>{identity.role === "secondary" ? "Appareil lié" : "Appareil maître"}</strong>
            <span>{identity.deviceLabel ?? "Appareil Quantic"}</span>
            <small>{identity.manifest ? `Manifeste V1.1 #${identity.manifest.payload.sequence}` : "Manifeste en attente"}</small>
            {outboxCount > 0 && <small>{outboxCount} livraison(s) chiffrée(s) en attente</small>}
          </div>
        </aside>

        {drawerOpen && <button className="qm-backdrop" onClick={() => setDrawerOpen(false)} aria-label="Fermer le menu" />}

        <section className="qm-list-panel">
          <div className="qm-list-head">
            <div><strong>{scope === "in" ? "Réception" : scope === "out" ? "Envoyés" : "Tous les messages"}</strong><small>{focusedMessages.length} message(s)</small></div>
            <button className="qm-text-btn" onClick={() => void sync()} disabled={syncing}>{syncing ? "Synchronisation…" : "Actualiser"}</button>
          </div>

          <div className="qm-message-list">
            {focusedMessages.length === 0 ? (
              <div className="qm-empty">
                <MailIcon name="mail" />
                <strong>Aucun message ici</strong>
                <span>{scope === "in" ? "Les nouveaux messages apparaîtront dans cette boîte." : "Aucun message pour ce filtre."}</span>
              </div>
            ) : focusedMessages.map((message) => {
              const correspondent = message.direction === "in" ? message.from : message.to;
              return (
                <button key={message.id} className={"qm-message-row " + (selectedMessageId === message.id ? "selected" : "")} onClick={() => setSelectedMessageId(message.id)}>
                  <span className={"qm-avatar " + (message.direction === "out" ? "out" : "")}>{mailInitial(correspondent)}</span>
                  <span className="qm-message-copy">
                    <span className="qm-message-line"><strong>{mailDisplayName(correspondent)}</strong><time>{formatMailDate(message.createdAt)}</time></span>
                    <span className="qm-subject">{message.subject || "Sans objet"}</span>
                    <span className="qm-preview">{message.body}</span>
                  </span>
                  {message.direction === "in" && <i className="qm-unread-dot" aria-hidden="true" />}
                </button>
              );
            })}
          </div>
        </section>

        <section className={"qm-reader " + (selectedMessage ? "open" : "")}>
          {selectedMessage ? (
            <>
              <div className="qm-reader-head">
                <button className="qm-icon-btn qm-reader-back" onClick={() => setSelectedMessageId(null)} aria-label="Retour"><MailIcon name="back" /></button>
                <div>
                  <strong>{selectedMessage.subject || "Sans objet"}</strong>
                  <small>{formatMailDate(selectedMessage.createdAt)}</small>
                </div>
              </div>
              <article className="qm-reader-body">
                <div className="qm-reader-person">
                  <span className="qm-avatar">{mailInitial(selectedMessage.direction === "in" ? selectedMessage.from : selectedMessage.to)}</span>
                  <div>
                    <strong>{mailDisplayName(selectedMessage.direction === "in" ? selectedMessage.from : selectedMessage.to)}</strong>
                    <small>{selectedMessage.direction === "in" ? `De ${selectedMessage.from}` : `À ${selectedMessage.to}`}</small>
                  </div>
                </div>
                <div className="qm-reader-message">{selectedMessage.body}</div>
              </article>
            </>
          ) : (
            <div className="qm-reader-placeholder">
              <MailIcon name="mail" />
              <strong>Sélectionnez un message</strong>
              <span>Le contenu s’affichera ici.</span>
            </div>
          )}
        </section>
      </div>

      <button className="qm-compose-fab" onClick={() => setComposeOpen(true)} aria-label="Nouveau message">
        <MailIcon name="compose" />
      </button>

      <nav className="qm-bottom-nav" aria-label="Navigation QuanticMail">
        <button className="active" onClick={() => { setScope("in"); setSelectedMessageId(null); }}><MailIcon name="mail" /><span>Courrier</span></button>
        <Link href="/devices"><MailIcon name="devices" /><span>Appareils</span></Link>
        <Link href="/vault"><MailIcon name="vault" /><span>Vault</span></Link>
        <Link href="/network"><MailIcon name="network" /><span>Network</span></Link>
      </nav>

      {composeOpen && (
        <div className="qm-compose-layer" role="dialog" aria-modal="true" aria-label="Nouveau message">
          <button className="qm-compose-backdrop" onClick={() => setComposeOpen(false)} aria-label="Fermer" />
          <section className="qm-compose-sheet">
            <header>
              <button className="qm-icon-btn" onClick={() => setComposeOpen(false)} aria-label="Fermer"><MailIcon name="close" /></button>
              <strong>Nouveau message</strong>
              <button className="qm-send-top" form="qm-compose-form" disabled={busy}>{busy ? "Envoi…" : "Envoyer"}</button>
            </header>
            <form id="qm-compose-form" onSubmit={sendMessage}>
              <label>À</label>
              <div className="qm-compose-address"><input value={to} onChange={(e) => setTo(e.target.value)} placeholder="nom" required /><span>@quantic</span></div>
              <label>Objet</label>
              <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Sans objet" />
              <label>Message</label>
              <textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="Écrire votre message…" rows={10} required />
              {(error || notice) && <p className={error ? "qn-error" : "qn-notice"}>{error || notice}</p>}
              <p className="qm-compose-security">Chiffrement Quantic · manifeste signé · one-time prekey si disponible.</p>
            </form>
          </section>
        </div>
      )}
    </main>
  );
}
