import { randomUUID } from "node:crypto";

import { verifyPortableEnvelope } from "./federation-node.mjs";
import type { QuanticPortableEnvelope } from "./federation-types.ts";
import { assertVerifiedManifest } from "./manifest-node.mjs";
import type { QuanticIdentityManifest } from "./manifest-types.ts";
import { RelayError, type QuanticPublicKey, type RelayEnvelope } from "./relay.ts";

const MAX_QUEUE = 500;

 type LocalIdentityRecord = {
  canonicalAddress: string;
  publicKey: QuanticPublicKey;
  signingPublicKey: QuanticPublicKey;
};

type LocalDeviceRecord = {
  canonicalAddress: string;
  deviceId: string;
  publicKey: QuanticPublicKey;
};

type LocalRelayState = {
  identities: Map<string, LocalIdentityRecord>;
  devices: Map<string, LocalDeviceRecord>;
  queues: Map<string, RelayEnvelope[]>;
};

function relayState() {
  const value = (globalThis as typeof globalThis & { __quanticRelayState?: LocalRelayState }).__quanticRelayState;
  if (!value) throw new RelayError("État Quantic Relay non initialisé.", 500);
  return value;
}

function sameP256Key(first: QuanticPublicKey, second: QuanticPublicKey) {
  return (
    first?.kty === "EC" &&
    second?.kty === "EC" &&
    first.crv === "P-256" &&
    second.crv === "P-256" &&
    first.x === second.x &&
    first.y === second.y
  );
}

function deviceKey(canonicalAddress: string, deviceId: string) {
  return `${canonicalAddress}#${deviceId}`;
}

function verificationError(error: unknown, status = 401): never {
  throw new RelayError(
    error instanceof Error ? error.message : "Preuve de fédération Quantic invalide.",
    status,
  );
}

export function enqueueFederatedEnvelope(input: {
  envelope: QuanticPortableEnvelope;
  senderIdentityManifest: QuanticIdentityManifest;
  recipientIdentityManifest: QuanticIdentityManifest;
  senderCryptoProfile?: unknown;
  nowMs?: number;
}) {
  const nowMs = input.nowMs ?? Date.now();
  let envelope: QuanticPortableEnvelope;
  let recipientManifest: QuanticIdentityManifest;
  try {
    envelope = verifyPortableEnvelope(
      input.envelope,
      input.senderIdentityManifest,
      input.senderCryptoProfile ?? null,
      nowMs,
    );
    recipientManifest = assertVerifiedManifest(input.recipientIdentityManifest);
  } catch (error) {
    verificationError(error);
  }

  if (envelope.to !== recipientManifest.payload.canonicalAddress) {
    throw new RelayError("Le manifeste destinataire ne correspond pas à l’enveloppe.", 400);
  }

  const revokedRecipient = recipientManifest.payload.revocations.some(
    (item) => item.deviceId === envelope.toDeviceId,
  );
  if (revokedRecipient) {
    throw new RelayError("Appareil Quantic destinataire révoqué.", 410);
  }
  const manifestDevice = recipientManifest.payload.devices.find(
    (item) => item.deviceId === envelope.toDeviceId,
  );
  if (!manifestDevice) {
    throw new RelayError("Appareil Quantic destinataire absent du manifeste.", 404);
  }

  const state = relayState();
  const localIdentity = state.identities.get(envelope.to);
  if (!localIdentity) {
    throw new RelayError("Identité Quantic destinataire non hébergée par ce relais.", 404);
  }
  if (
    !sameP256Key(localIdentity.signingPublicKey, recipientManifest.payload.identitySigningPublicKey) ||
    !sameP256Key(localIdentity.publicKey, recipientManifest.payload.identityPublicKey)
  ) {
    throw new RelayError("Le manifeste destinataire ne correspond pas à l’identité locale.", 409);
  }

  const localDevice = state.devices.get(deviceKey(envelope.to, envelope.toDeviceId));
  if (!localDevice || !sameP256Key(localDevice.publicKey, manifestDevice.publicKey)) {
    throw new RelayError("Appareil Quantic destinataire non hébergé ou incohérent.", 404);
  }

  if (!envelope.classicalEphemeralPublicKey) {
    throw new RelayError("Clé éphémère classique requise pour Federation V1.", 400);
  }

  const queueKey = deviceKey(envelope.to, envelope.toDeviceId);
  const queue = state.queues.get(queueKey) ?? [];
  const existing = queue.find(
    (item) =>
      item.from === envelope.from &&
      item.fromDeviceId === envelope.fromDeviceId &&
      item.clientMessageId === envelope.clientMessageId,
  );
  if (existing) {
    return { id: existing.id, queuedAt: existing.createdAt, duplicate: true };
  }
  if (queue.length >= MAX_QUEUE) {
    throw new RelayError("File d’attente de l’appareil destinataire saturée.", 507);
  }

  const stored: RelayEnvelope = {
    id: randomUUID(),
    clientMessageId: envelope.clientMessageId,
    from: envelope.from,
    fromDeviceId: envelope.fromDeviceId,
    to: envelope.to,
    toDeviceId: envelope.toDeviceId,
    ciphertext: envelope.ciphertext,
    iv: envelope.iv,
    ephemeralPublicKey: envelope.classicalEphemeralPublicKey,
    createdAt: envelope.createdAt,
  };
  queue.push(stored);
  state.queues.set(queueKey, queue);
  return { id: stored.id, queuedAt: stored.createdAt, duplicate: false };
}
