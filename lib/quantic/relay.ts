import {
  createHash,
  createPublicKey,
  randomBytes,
  randomUUID,
  timingSafeEqual,
  verify,
} from "node:crypto";
import {
  assertDeviceIdMatchesDigest,
  deviceIdFromDigestHex,
  isValidDeviceId,
} from "./device-id-core.mjs";
import { identityNamesForKey } from "./identity-names.mjs";

export type QuanticPublicKey = JsonWebKey;

export type RelayEnvelope = {
  id: string;
  clientMessageId: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  ciphertext: string;
  iv: string;
  ephemeralPublicKey: QuanticPublicKey;
  createdAt: string;
};

export type DeliveryReceipt = {
  id: string;
  clientMessageId: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  deliveredAt: string;
};

type IdentityRecord = {
  handle: string;
  address: string;
  canonicalAddress: string;
  fingerprint: string;
  publicKey: QuanticPublicKey;
  signingPublicKey: QuanticPublicKey;
  authTokenHash: string;
  createdAt: string;
  updatedAt: string;
};

type DeviceRecord = {
  canonicalAddress: string;
  deviceId: string;
  label: string;
  publicKey: QuanticPublicKey;
  deviceSigningPublicKey: QuanticPublicKey;
  authTokenHash: string;
  kind: "root" | "linked";
  createdAt: string;
  updatedAt: string;
};

type DeviceCertificatePayload = {
  version: 1;
  canonicalAddress: string;
  handle: string;
  fingerprint: string;
  identityPublicKey: QuanticPublicKey;
  identitySigningPublicKey: QuanticPublicKey;
  deviceId: string;
  deviceLabel: string;
  devicePublicKey: QuanticPublicKey;
  deviceSigningPublicKey: QuanticPublicKey;
  issuedAt: string;
};

type DeviceCertificate = {
  format: "quantic-device-certificate";
  version: 1;
  payload: DeviceCertificatePayload;
  signature: string;
};

type ChallengeRecord = {
  challenge: string;
  handle: string;
  canonicalAddress: string;
  fingerprint: string;
  publicKey: QuanticPublicKey;
  signingPublicKey: QuanticPublicKey;
  expiresAt: number;
};

type RelayState = {
  identities: Map<string, IdentityRecord>;
  aliases: Map<string, Set<string>>;
  challenges: Map<string, ChallengeRecord>;
  devices: Map<string, DeviceRecord>;
  queues: Map<string, RelayEnvelope[]>;
  receipts: Map<string, DeliveryReceipt[]>;
  sendWindows: Map<string, number[]>;
};

declare global {
  var __quanticRelayState: RelayState | undefined;
}

const state: RelayState = globalThis.__quanticRelayState ?? {
  identities: new Map(),
  aliases: new Map(),
  challenges: new Map(),
  devices: new Map(),
  queues: new Map(),
  receipts: new Map(),
  sendWindows: new Map(),
};
if (!state.aliases) state.aliases = new Map();
if (!state.challenges) state.challenges = new Map();
if (!state.devices) state.devices = new Map();
if (!state.receipts) state.receipts = new Map();
globalThis.__quanticRelayState = state;

const HANDLE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const FINGERPRINT = /^(?:[0-9a-f]{10}|[0-9a-f]{32})$/;
const CLIENT_MESSAGE_ID = /^[a-zA-Z0-9._:-]{8,100}$/;
const MAX_QUEUE = 500;
const MAX_RECEIPTS = 500;
const MAX_CIPHERTEXT_CHARS = 400_000;
const MESSAGE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const SENDS_PER_MINUTE = 60;

export class RelayError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
  }
}

export function normalizeLocator(value: string) {
  return value.trim().toLowerCase().replace(/@quantic$/i, "");
}

function parseLocator(value: string) {
  const clean = normalizeLocator(value);
  const separator = clean.lastIndexOf("~");
  const handle = separator >= 0 ? clean.slice(0, separator) : clean;
  const fingerprint = separator >= 0 ? clean.slice(separator + 1) : null;
  if (!HANDLE.test(handle)) throw new RelayError("Identifiant Quantic invalide.", 400);
  if (fingerprint && !FINGERPRINT.test(fingerprint)) throw new RelayError("Empreinte Quantic invalide.", 400);
  return { handle, fingerprint };
}

function validateEncryptionPublicKey(key: QuanticPublicKey) {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new RelayError("Clé publique de chiffrement invalide.", 400);
  }
}

function validateSigningPublicKey(key: QuanticPublicKey) {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new RelayError("Clé publique de signature invalide.", 400);
  }
}

function deviceDigestForKey(key: QuanticPublicKey) {
  validateEncryptionPublicKey(key);
  return createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex");
}

function deviceIdForKey(key: QuanticPublicKey, length: 10 | 32) {
  return deviceIdFromDigestHex(deviceDigestForKey(key), length);
}

function assertDeviceIdForKey(deviceId: string, key: QuanticPublicKey) {
  try {
    return assertDeviceIdMatchesDigest(deviceId, deviceDigestForKey(key));
  } catch (error) {
    throw new RelayError(
      error instanceof Error ? error.message : "Identifiant cryptographique de l’appareil invalide.",
      400,
    );
  }
}

function identityNames(
  handle: string,
  signingPublicKey: QuanticPublicKey,
  requestedFingerprint: string | null = null,
) {
  validateSigningPublicKey(signingPublicKey);
  try {
    return identityNamesForKey(handle, signingPublicKey, requestedFingerprint);
  } catch (error) {
    throw new RelayError(error instanceof Error ? error.message : "Identité Quantic invalide.", 400);
  }
}

function tokenHash(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

function tokenMatches(expectedHash: string, token: string) {
  if (!expectedHash) return false;
  const actual = Buffer.from(tokenHash(token), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function addAlias(handle: string, canonicalAddress: string) {
  const aliases = state.aliases.get(handle) ?? new Set<string>();
  aliases.add(canonicalAddress);
  state.aliases.set(handle, aliases);
}

function deviceKey(canonicalAddress: string, deviceId: string) {
  return `${canonicalAddress}#${deviceId}`;
}

function mailboxKey(canonicalAddress: string, deviceId: string) {
  return `${canonicalAddress}#${deviceId}`;
}

function existingRootDevice(identity: IdentityRecord) {
  return [...state.devices.values()].find(
    (device) =>
      device.canonicalAddress === identity.canonicalAddress &&
      device.kind === "root" &&
      JSON.stringify(device.publicKey) === JSON.stringify(identity.publicKey),
  ) ?? null;
}

function rootDeviceIdForIdentity(identity: IdentityRecord) {
  const existing = existingRootDevice(identity);
  if (existing) return existing.deviceId;
  return deviceIdForKey(identity.publicKey, identity.fingerprint.length === 32 ? 32 : 10);
}

function resolveRecord(locatorInput: string) {
  const locator = parseLocator(locatorInput);
  if (locator.fingerprint) {
    const canonical = `${locator.handle}~${locator.fingerprint}@quantic`;
    const identity = state.identities.get(canonical);
    if (!identity) throw new RelayError(`${canonical} est introuvable.`, 404);
    return identity;
  }

  const candidates = [...(state.aliases.get(locator.handle) ?? [])]
    .map((canonical) => state.identities.get(canonical))
    .filter((item): item is IdentityRecord => Boolean(item));
  if (candidates.length === 0) throw new RelayError(`${locator.handle}@quantic est introuvable.`, 404);
  if (candidates.length > 1) {
    throw new RelayError(
      `${locator.handle}@quantic est ambigu. Utilisez l’adresse Quantic canonique avec son empreinte.`,
      409,
    );
  }
  return candidates[0];
}

function ensureClientMessageId(value: string) {
  const id = value.trim();
  if (!CLIENT_MESSAGE_ID.test(id)) throw new RelayError("Identifiant de message invalide.", 400);
  return id;
}

function cleanDeviceLabel(value: string) {
  const label = value.trim().replace(/\s+/g, " ");
  if (label.length < 2 || label.length > 48) throw new RelayError("Nom d’appareil invalide.", 400);
  return label;
}

function certificateMessage(payload: DeviceCertificatePayload) {
  return [
    "quantic-device-certificate-v1",
    payload.canonicalAddress,
    payload.handle,
    payload.fingerprint,
    `P-256:${payload.identityPublicKey.x}:${payload.identityPublicKey.y}`,
    `P-256:${payload.identitySigningPublicKey.x}:${payload.identitySigningPublicKey.y}`,
    payload.deviceId,
    payload.deviceLabel,
    `P-256:${payload.devicePublicKey.x}:${payload.devicePublicKey.y}`,
    `P-256:${payload.deviceSigningPublicKey.x}:${payload.deviceSigningPublicKey.y}`,
    payload.issuedAt,
  ].join("\n");
}

function verifyRawSignature(publicKey: QuanticPublicKey, text: string, signature: string) {
  try {
    return verify(
      "sha256",
      Buffer.from(text, "utf8"),
      {
        key: createPublicKey({ key: publicKey, format: "jwk" }),
        dsaEncoding: "ieee-p1363",
      },
      Buffer.from(signature, "base64"),
    );
  } catch {
    return false;
  }
}

function publicDevices(identity: IdentityRecord) {
  const rootDeviceId = rootDeviceIdForIdentity(identity);
  const rootRecord = state.devices.get(deviceKey(identity.canonicalAddress, rootDeviceId));
  const linked = [...state.devices.values()]
    .filter((device) => device.canonicalAddress === identity.canonicalAddress && device.kind === "linked")
    .map((device) => ({
      deviceId: device.deviceId,
      label: device.label,
      publicKey: device.publicKey,
      deviceSigningPublicKey: device.deviceSigningPublicKey,
      kind: device.kind,
    }));
  return [
    {
      deviceId: rootDeviceId,
      label: rootRecord?.label ?? "Appareil principal",
      publicKey: identity.publicKey,
      deviceSigningPublicKey: rootRecord?.deviceSigningPublicKey ?? identity.signingPublicKey,
      kind: "root" as const,
    },
    ...linked,
  ];
}

function findPublicDevice(identity: IdentityRecord, deviceId: string) {
  const device = publicDevices(identity).find((item) => item.deviceId === deviceId);
  if (!device) throw new RelayError("Appareil Quantic destinataire introuvable.", 404);
  return device;
}

function authenticateDevice(locatorInput: string, authToken: string | null, requestedDeviceId?: string | null) {
  if (!authToken) throw new RelayError("Authentification Quantic invalide.", 401);
  const identity = resolveRecord(locatorInput);
  const rootDeviceId = rootDeviceIdForIdentity(identity);

  if (requestedDeviceId) {
    if (!isValidDeviceId(requestedDeviceId)) throw new RelayError("Identifiant d’appareil invalide.", 400);
    if (requestedDeviceId === rootDeviceId && tokenMatches(identity.authTokenHash, authToken)) {
      return { identity, deviceId: rootDeviceId };
    }
    const linked = state.devices.get(deviceKey(identity.canonicalAddress, requestedDeviceId));
    if (linked && tokenMatches(linked.authTokenHash, authToken)) {
      return { identity, deviceId: linked.deviceId };
    }
    throw new RelayError("Authentification de l’appareil Quantic invalide.", 401);
  }

  const matches: string[] = [];
  if (tokenMatches(identity.authTokenHash, authToken)) matches.push(rootDeviceId);
  for (const device of state.devices.values()) {
    if (
      device.canonicalAddress === identity.canonicalAddress &&
      device.kind === "linked" &&
      tokenMatches(device.authTokenHash, authToken)
    ) {
      matches.push(device.deviceId);
    }
  }
  if (matches.length !== 1) throw new RelayError("Authentification Quantic invalide.", 401);
  return { identity, deviceId: matches[0] };
}

export function authenticateLocalDevice(
  locatorInput: string,
  authToken: string | null,
  requestedDeviceId?: string | null,
) {
  const authenticated = authenticateDevice(locatorInput, authToken, requestedDeviceId);
  return {
    canonicalAddress: authenticated.identity.canonicalAddress,
    deviceId: authenticated.deviceId,
    publicKey: authenticated.identity.publicKey,
    signingPublicKey: authenticated.identity.signingPublicKey,
  };
}

function pruneQueue(key: string) {
  const queue = state.queues.get(key);
  if (!queue) return;
  const cutoff = Date.now() - MESSAGE_TTL_MS;
  const fresh = queue.filter((item) => Date.parse(item.createdAt) >= cutoff);
  if (fresh.length) state.queues.set(key, fresh);
  else state.queues.delete(key);
}

function pruneReceipts(key: string) {
  const receipts = state.receipts.get(key);
  if (!receipts) return;
  const cutoff = Date.now() - MESSAGE_TTL_MS;
  const fresh = receipts.filter((item) => Date.parse(item.deliveredAt) >= cutoff);
  if (fresh.length) state.receipts.set(key, fresh);
  else state.receipts.delete(key);
}

function checkSendRate(canonicalAddress: string) {
  const now = Date.now();
  const recent = (state.sendWindows.get(canonicalAddress) ?? []).filter((stamp) => stamp >= now - 60_000);
  if (recent.length >= SENDS_PER_MINUTE) throw new RelayError("Trop d’envois. Réessayez dans une minute.", 429);
  recent.push(now);
  state.sendWindows.set(canonicalAddress, recent);
}

function consumeProof(input: {
  canonicalAddress: string;
  challenge?: string;
  signature?: string;
  publicKey: QuanticPublicKey;
  signingPublicKey: QuanticPublicKey;
}) {
  if (!input.challenge || !input.signature) throw new RelayError("Preuve de propriété Quantic requise.", 428);
  const stored = state.challenges.get(input.canonicalAddress);
  if (!stored || stored.challenge !== input.challenge || stored.expiresAt < Date.now()) {
    throw new RelayError("Défi Quantic expiré. Recommencez l’enregistrement.", 428);
  }
  if (
    JSON.stringify(stored.publicKey) !== JSON.stringify(input.publicKey) ||
    JSON.stringify(stored.signingPublicKey) !== JSON.stringify(input.signingPublicKey)
  ) {
    throw new RelayError("Les clés du défi Quantic ne correspondent pas.", 401);
  }
  state.challenges.delete(input.canonicalAddress);
  if (!verifyRawSignature(input.signingPublicKey, input.challenge, input.signature)) {
    throw new RelayError("Signature de propriété Quantic invalide.", 401);
  }
}

export function createIdentityChallenge(input: {
  handle: string;
  publicKey: QuanticPublicKey;
  signingPublicKey: QuanticPublicKey;
}) {
  const locator = parseLocator(input.handle);
  validateEncryptionPublicKey(input.publicKey);
  validateSigningPublicKey(input.signingPublicKey);
  const names = identityNames(locator.handle, input.signingPublicKey, locator.fingerprint);
  const challenge = randomBytes(32).toString("base64url");
  state.challenges.set(names.canonicalAddress, {
    challenge,
    handle: locator.handle,
    canonicalAddress: names.canonicalAddress,
    fingerprint: names.fingerprint,
    publicKey: input.publicKey,
    signingPublicKey: input.signingPublicKey,
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
  });
  return { ...names, challenge, expiresInSeconds: CHALLENGE_TTL_MS / 1000 };
}

export function registerIdentity(input: {
  handle: string;
  publicKey: QuanticPublicKey;
  signingPublicKey: QuanticPublicKey;
  authToken: string;
  deviceId?: string;
  challenge?: string;
  signature?: string;
}) {
  const locator = parseLocator(input.handle);
  validateEncryptionPublicKey(input.publicKey);
  validateSigningPublicKey(input.signingPublicKey);
  if (input.authToken.length < 40) throw new RelayError("Jeton d’appareil invalide.", 400);
  if (input.deviceId) assertDeviceIdForKey(input.deviceId, input.publicKey);

  const names = identityNames(locator.handle, input.signingPublicKey, locator.fingerprint);
  const existing = state.identities.get(names.canonicalAddress);
  const alreadyAuthenticated = existing && tokenMatches(existing.authTokenHash, input.authToken);
  if (!alreadyAuthenticated) {
    consumeProof({
      canonicalAddress: names.canonicalAddress,
      challenge: input.challenge,
      signature: input.signature,
      publicKey: input.publicKey,
      signingPublicKey: input.signingPublicKey,
    });
  }

  if (existing) {
    if (
      JSON.stringify(existing.signingPublicKey) !== JSON.stringify(input.signingPublicKey) ||
      JSON.stringify(existing.publicKey) !== JSON.stringify(input.publicKey)
    ) {
      throw new RelayError("Les clés de l’identité racine ne correspondent pas.", 409);
    }
  }

  const now = new Date().toISOString();
  const identity: IdentityRecord = {
    handle: locator.handle,
    ...names,
    publicKey: input.publicKey,
    signingPublicKey: input.signingPublicKey,
    authTokenHash: tokenHash(input.authToken),
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  state.identities.set(names.canonicalAddress, identity);
  addAlias(locator.handle, names.canonicalAddress);

  const priorRoot = existingRootDevice(identity);
  const rootDeviceId = priorRoot?.deviceId ?? input.deviceId ?? deviceIdForKey(input.publicKey, 10);
  const existingRoot = state.devices.get(deviceKey(names.canonicalAddress, rootDeviceId));
  state.devices.set(deviceKey(names.canonicalAddress, rootDeviceId), {
    canonicalAddress: names.canonicalAddress,
    deviceId: rootDeviceId,
    label: existingRoot?.label ?? priorRoot?.label ?? "Appareil principal",
    publicKey: input.publicKey,
    deviceSigningPublicKey: input.signingPublicKey,
    authTokenHash: tokenHash(input.authToken),
    kind: "root",
    createdAt: existingRoot?.createdAt ?? priorRoot?.createdAt ?? now,
    updatedAt: now,
  });

  return {
    address: names.address,
    canonicalAddress: names.canonicalAddress,
    fingerprint: names.fingerprint,
    publicKey: input.publicKey,
    signingPublicKey: input.signingPublicKey,
    rootDeviceId,
    devices: publicDevices(identity),
  };
}

export function registerAuthorizedDevice(input: {
  certificate: DeviceCertificate;
  authToken: string;
}) {
  const certificate = input.certificate;
  if (
    certificate?.format !== "quantic-device-certificate" ||
    certificate.version !== 1 ||
    certificate.payload?.version !== 1 ||
    typeof certificate.signature !== "string"
  ) {
    throw new RelayError("Certificat d’appareil Quantic invalide.", 400);
  }
  if (input.authToken.length < 40) throw new RelayError("Jeton d’appareil invalide.", 400);

  const payload = certificate.payload;
  const { handle, fingerprint } = parseLocator(payload.canonicalAddress);
  if (!fingerprint || handle !== payload.handle || fingerprint !== payload.fingerprint) {
    throw new RelayError("Identité canonique du certificat invalide.", 400);
  }
  validateEncryptionPublicKey(payload.identityPublicKey);
  validateSigningPublicKey(payload.identitySigningPublicKey);
  validateEncryptionPublicKey(payload.devicePublicKey);
  validateSigningPublicKey(payload.deviceSigningPublicKey);
  const names = identityNames(payload.handle, payload.identitySigningPublicKey, payload.fingerprint);
  assertDeviceIdForKey(payload.deviceId, payload.devicePublicKey);
  if (cleanDeviceLabel(payload.deviceLabel) !== payload.deviceLabel) {
    throw new RelayError("Nom d’appareil non canonique.", 400);
  }
  if (!verifyRawSignature(payload.identitySigningPublicKey, certificateMessage(payload), certificate.signature)) {
    throw new RelayError("Signature du certificat d’appareil invalide.", 401);
  }

  if (names.canonicalAddress !== payload.canonicalAddress) {
    throw new RelayError("Adresse canonique du certificat incohérente.", 400);
  }

  const existingIdentity = state.identities.get(names.canonicalAddress);
  if (existingIdentity) {
    if (
      JSON.stringify(existingIdentity.signingPublicKey) !== JSON.stringify(payload.identitySigningPublicKey) ||
      JSON.stringify(existingIdentity.publicKey) !== JSON.stringify(payload.identityPublicKey)
    ) {
      throw new RelayError("Le certificat ne correspond pas à l’identité enregistrée.", 409);
    }
  }

  const now = new Date().toISOString();
  const identity: IdentityRecord = existingIdentity ?? {
    handle: payload.handle,
    ...names,
    publicKey: payload.identityPublicKey,
    signingPublicKey: payload.identitySigningPublicKey,
    authTokenHash: "",
    createdAt: payload.issuedAt || now,
    updatedAt: now,
  };
  identity.updatedAt = now;
  state.identities.set(names.canonicalAddress, identity);
  addAlias(payload.handle, names.canonicalAddress);

  const existingDevice = state.devices.get(deviceKey(names.canonicalAddress, payload.deviceId));
  if (existingDevice && JSON.stringify(existingDevice.publicKey) !== JSON.stringify(payload.devicePublicKey)) {
    throw new RelayError("Un autre appareil utilise déjà cet identifiant cryptographique.", 409);
  }

  state.devices.set(deviceKey(names.canonicalAddress, payload.deviceId), {
    canonicalAddress: names.canonicalAddress,
    deviceId: payload.deviceId,
    label: payload.deviceLabel,
    publicKey: payload.devicePublicKey,
    deviceSigningPublicKey: payload.deviceSigningPublicKey,
    authTokenHash: tokenHash(input.authToken),
    kind: "linked",
    createdAt: existingDevice?.createdAt ?? now,
    updatedAt: now,
  });

  return {
    address: identity.address,
    canonicalAddress: identity.canonicalAddress,
    fingerprint: identity.fingerprint,
    publicKey: identity.publicKey,
    signingPublicKey: identity.signingPublicKey,
    deviceId: payload.deviceId,
    devices: publicDevices(identity),
  };
}

export function resolveIdentity(locatorInput: string) {
  const identity = resolveRecord(locatorInput);
  return {
    address: identity.address,
    canonicalAddress: identity.canonicalAddress,
    fingerprint: identity.fingerprint,
    publicKey: identity.publicKey,
    signingPublicKey: identity.signingPublicKey,
    devices: publicDevices(identity),
  };
}

export function enqueueEnvelope(input: {
  clientMessageId: string;
  from: string;
  fromDeviceId?: string | null;
  to: string;
  toDeviceId: string;
  authToken: string | null;
  ciphertext: string;
  iv: string;
  ephemeralPublicKey: QuanticPublicKey;
}) {
  const senderAuth = authenticateDevice(input.from, input.authToken, input.fromDeviceId);
  const recipient = resolveRecord(input.to);
  const recipientDevice = findPublicDevice(recipient, input.toDeviceId);
  const clientMessageId = ensureClientMessageId(input.clientMessageId);
  validateEncryptionPublicKey(input.ephemeralPublicKey);
  if (!input.iv || !input.ciphertext || input.ciphertext.length > MAX_CIPHERTEXT_CHARS) {
    throw new RelayError("Enveloppe chiffrée invalide ou trop volumineuse.", 400);
  }

  checkSendRate(senderAuth.identity.canonicalAddress);
  const queueKey = mailboxKey(recipient.canonicalAddress, recipientDevice.deviceId);
  pruneQueue(queueKey);
  const queue = state.queues.get(queueKey) ?? [];
  const existing = queue.find(
    (item) =>
      item.from === senderAuth.identity.canonicalAddress &&
      item.fromDeviceId === senderAuth.deviceId &&
      item.clientMessageId === clientMessageId,
  );
  if (existing) return { id: existing.id, queuedAt: existing.createdAt, duplicate: true };
  if (queue.length >= MAX_QUEUE) throw new RelayError("File d’attente de l’appareil destinataire saturée.", 507);

  const envelope: RelayEnvelope = {
    id: randomUUID(),
    clientMessageId,
    from: senderAuth.identity.canonicalAddress,
    fromDeviceId: senderAuth.deviceId,
    to: recipient.canonicalAddress,
    toDeviceId: recipientDevice.deviceId,
    ciphertext: input.ciphertext,
    iv: input.iv,
    ephemeralPublicKey: input.ephemeralPublicKey,
    createdAt: new Date().toISOString(),
  };
  queue.push(envelope);
  state.queues.set(queueKey, queue);
  return { id: envelope.id, queuedAt: envelope.createdAt, duplicate: false };
}

export function pullEnvelopes(
  locatorInput: string,
  authToken: string | null,
  deviceId?: string | null,
) {
  const auth = authenticateDevice(locatorInput, authToken, deviceId);
  const key = mailboxKey(auth.identity.canonicalAddress, auth.deviceId);
  pruneQueue(key);
  return (state.queues.get(key) ?? []).slice(0, 100);
}

export function acknowledgeEnvelopes(
  locatorInput: string,
  authToken: string | null,
  deviceId: string | null | undefined,
  ids: string[],
) {
  const auth = authenticateDevice(locatorInput, authToken, deviceId);
  const key = mailboxKey(auth.identity.canonicalAddress, auth.deviceId);
  const idSet = new Set(ids.filter((id) => typeof id === "string" && id.length <= 100));
  const queue = state.queues.get(key) ?? [];
  const acknowledged = queue.filter((item) => idSet.has(item.id));
  const next = queue.filter((item) => !idSet.has(item.id));

  for (const envelope of acknowledged) {
    const receiptKey = mailboxKey(envelope.from, envelope.fromDeviceId);
    pruneReceipts(receiptKey);
    const receipts = state.receipts.get(receiptKey) ?? [];
    const duplicate = receipts.some((receipt) => receipt.clientMessageId === envelope.clientMessageId);
    if (!duplicate && receipts.length < MAX_RECEIPTS) {
      receipts.push({
        id: randomUUID(),
        clientMessageId: envelope.clientMessageId,
        from: envelope.from,
        fromDeviceId: envelope.fromDeviceId,
        to: envelope.to,
        toDeviceId: envelope.toDeviceId,
        deliveredAt: new Date().toISOString(),
      });
      state.receipts.set(receiptKey, receipts);
    }
  }

  if (next.length) state.queues.set(key, next);
  else state.queues.delete(key);
  return { acknowledged: acknowledged.length };
}

export function enqueueDeliveryReceipt(input: Omit<DeliveryReceipt, "id"> & { id?: string }) {
  const sender = resolveRecord(input.from);
  const senderDevice = findPublicDevice(sender, input.fromDeviceId);
  const clientMessageId = ensureClientMessageId(input.clientMessageId);
  if (sender.canonicalAddress !== input.from || senderDevice.deviceId !== input.fromDeviceId) {
    throw new RelayError("Destinataire du reçu Quantic non hébergé localement.", 404);
  }
  if (typeof input.deliveredAt !== "string" || Number.isNaN(Date.parse(input.deliveredAt))) {
    throw new RelayError("Date de reçu Quantic invalide.", 400);
  }
  const receiptKey = mailboxKey(sender.canonicalAddress, senderDevice.deviceId);
  pruneReceipts(receiptKey);
  const receipts = state.receipts.get(receiptKey) ?? [];
  const existing = receipts.find((receipt) => receipt.clientMessageId === clientMessageId);
  if (existing) return { id: existing.id, duplicate: true };
  if (receipts.length >= MAX_RECEIPTS) throw new RelayError("File de reçus Quantic saturée.", 507);
  const receipt: DeliveryReceipt = {
    id: input.id ?? randomUUID(),
    clientMessageId,
    from: input.from,
    fromDeviceId: input.fromDeviceId,
    to: input.to,
    toDeviceId: input.toDeviceId,
    deliveredAt: input.deliveredAt,
  };
  receipts.push(receipt);
  state.receipts.set(receiptKey, receipts);
  return { id: receipt.id, duplicate: false };
}

export function pullReceipts(
  locatorInput: string,
  authToken: string | null,
  deviceId?: string | null,
) {
  const auth = authenticateDevice(locatorInput, authToken, deviceId);
  const key = mailboxKey(auth.identity.canonicalAddress, auth.deviceId);
  pruneReceipts(key);
  return (state.receipts.get(key) ?? []).slice(0, 100);
}

export function acknowledgeReceipts(
  locatorInput: string,
  authToken: string | null,
  deviceId: string | null | undefined,
  ids: string[],
) {
  const auth = authenticateDevice(locatorInput, authToken, deviceId);
  const key = mailboxKey(auth.identity.canonicalAddress, auth.deviceId);
  const idSet = new Set(ids.filter((id) => typeof id === "string" && id.length <= 100));
  const receipts = state.receipts.get(key) ?? [];
  const next = receipts.filter((item) => !idSet.has(item.id));
  if (next.length) state.receipts.set(key, next);
  else state.receipts.delete(key);
  return { acknowledged: receipts.length - next.length };
}
