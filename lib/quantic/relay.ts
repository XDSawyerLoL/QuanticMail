import {
  createHash,
  createPublicKey,
  randomBytes,
  randomUUID,
  timingSafeEqual,
  verify,
} from "node:crypto";

export type QuanticPublicKey = JsonWebKey;

export type RelayEnvelope = {
  id: string;
  clientMessageId: string;
  from: string;
  to: string;
  ciphertext: string;
  iv: string;
  ephemeralPublicKey: QuanticPublicKey;
  createdAt: string;
};

export type DeliveryReceipt = {
  id: string;
  clientMessageId: string;
  from: string;
  to: string;
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
  queues: new Map(),
  receipts: new Map(),
  sendWindows: new Map(),
};
if (!state.aliases) state.aliases = new Map();
if (!state.challenges) state.challenges = new Map();
if (!state.receipts) state.receipts = new Map();
globalThis.__quanticRelayState = state;

const HANDLE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const FINGERPRINT = /^[0-9a-f]{10}$/;
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
  if (!HANDLE.test(handle)) {
    throw new RelayError("Identifiant Quantic invalide.", 400);
  }
  if (fingerprint && !FINGERPRINT.test(fingerprint)) {
    throw new RelayError("Empreinte Quantic invalide.", 400);
  }
  return { handle, fingerprint };
}

function validateEncryptionPublicKey(key: QuanticPublicKey) {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new RelayError("Clé publique de chiffrement invalide.", 400);
  }
}

function validateSigningPublicKey(key: QuanticPublicKey) {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new RelayError("Clé publique d’identité invalide.", 400);
  }
}

function fingerprintPublicKey(key: QuanticPublicKey) {
  validateSigningPublicKey(key);
  return createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex")
    .slice(0, 10);
}

function identityNames(handle: string, signingPublicKey: QuanticPublicKey) {
  const fingerprint = fingerprintPublicKey(signingPublicKey);
  return {
    fingerprint,
    address: `${handle}@quantic`,
    canonicalAddress: `${handle}~${fingerprint}@quantic`,
  };
}

function tokenHash(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

function tokenMatches(expectedHash: string, token: string) {
  const actual = Buffer.from(tokenHash(token), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function addAlias(handle: string, canonicalAddress: string) {
  const aliases = state.aliases.get(handle) ?? new Set<string>();
  aliases.add(canonicalAddress);
  state.aliases.set(handle, aliases);
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
  if (candidates.length === 0) {
    throw new RelayError(`${locator.handle}@quantic est introuvable.`, 404);
  }
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

function pruneQueue(canonicalAddress: string) {
  const queue = state.queues.get(canonicalAddress);
  if (!queue) return;
  const cutoff = Date.now() - MESSAGE_TTL_MS;
  const fresh = queue.filter((item) => Date.parse(item.createdAt) >= cutoff);
  if (fresh.length) state.queues.set(canonicalAddress, fresh);
  else state.queues.delete(canonicalAddress);
}

function pruneReceipts(canonicalAddress: string) {
  const receipts = state.receipts.get(canonicalAddress);
  if (!receipts) return;
  const cutoff = Date.now() - MESSAGE_TTL_MS;
  const fresh = receipts.filter((item) => Date.parse(item.deliveredAt) >= cutoff);
  if (fresh.length) state.receipts.set(canonicalAddress, fresh);
  else state.receipts.delete(canonicalAddress);
}

function checkSendRate(canonicalAddress: string) {
  const now = Date.now();
  const recent = (state.sendWindows.get(canonicalAddress) ?? []).filter((stamp) => stamp >= now - 60_000);
  if (recent.length >= SENDS_PER_MINUTE) {
    throw new RelayError("Trop d’envois. Réessayez dans une minute.", 429);
  }
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
  if (!input.challenge || !input.signature) {
    throw new RelayError("Preuve de propriété Quantic requise.", 428);
  }
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
  let valid = false;
  try {
    valid = verify(
      "sha256",
      Buffer.from(input.challenge, "utf8"),
      {
        key: createPublicKey({ key: input.signingPublicKey, format: "jwk" }),
        dsaEncoding: "ieee-p1363",
      },
      Buffer.from(input.signature, "base64"),
    );
  } catch {
    valid = false;
  }
  state.challenges.delete(input.canonicalAddress);
  if (!valid) throw new RelayError("Signature de propriété Quantic invalide.", 401);
}

export function createIdentityChallenge(input: {
  handle: string;
  publicKey: QuanticPublicKey;
  signingPublicKey: QuanticPublicKey;
}) {
  const { handle } = parseLocator(input.handle);
  validateEncryptionPublicKey(input.publicKey);
  validateSigningPublicKey(input.signingPublicKey);
  const names = identityNames(handle, input.signingPublicKey);
  const challenge = randomBytes(32).toString("base64url");
  state.challenges.set(names.canonicalAddress, {
    challenge,
    handle,
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
  challenge?: string;
  signature?: string;
}) {
  const { handle } = parseLocator(input.handle);
  validateEncryptionPublicKey(input.publicKey);
  validateSigningPublicKey(input.signingPublicKey);
  if (input.authToken.length < 40) throw new RelayError("Jeton d’appareil invalide.", 400);

  const names = identityNames(handle, input.signingPublicKey);
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

  const now = new Date().toISOString();
  const identity: IdentityRecord = {
    handle,
    ...names,
    publicKey: input.publicKey,
    signingPublicKey: input.signingPublicKey,
    authTokenHash: tokenHash(input.authToken),
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  state.identities.set(names.canonicalAddress, identity);
  addAlias(handle, names.canonicalAddress);
  return {
    address: names.address,
    canonicalAddress: names.canonicalAddress,
    fingerprint: names.fingerprint,
    publicKey: input.publicKey,
    signingPublicKey: input.signingPublicKey,
  };
}

export function authenticate(locatorInput: string, authToken: string | null) {
  if (!authToken) throw new RelayError("Authentification Quantic invalide.", 401);
  const locator = parseLocator(locatorInput);
  if (locator.fingerprint) {
    const identity = resolveRecord(locatorInput);
    if (!tokenMatches(identity.authTokenHash, authToken)) {
      throw new RelayError("Authentification Quantic invalide.", 401);
    }
    return identity;
  }
  const candidates = [...(state.aliases.get(locator.handle) ?? [])]
    .map((canonical) => state.identities.get(canonical))
    .filter((item): item is IdentityRecord => Boolean(item))
    .filter((item) => tokenMatches(item.authTokenHash, authToken));
  if (candidates.length !== 1) throw new RelayError("Authentification Quantic invalide.", 401);
  return candidates[0];
}

export function resolveIdentity(locatorInput: string) {
  const identity = resolveRecord(locatorInput);
  return {
    address: identity.address,
    canonicalAddress: identity.canonicalAddress,
    fingerprint: identity.fingerprint,
    publicKey: identity.publicKey,
    signingPublicKey: identity.signingPublicKey,
  };
}

export function enqueueEnvelope(input: {
  clientMessageId: string;
  from: string;
  to: string;
  authToken: string | null;
  ciphertext: string;
  iv: string;
  ephemeralPublicKey: QuanticPublicKey;
}) {
  const sender = authenticate(input.from, input.authToken);
  const recipient = resolveRecord(input.to);
  const clientMessageId = ensureClientMessageId(input.clientMessageId);
  validateEncryptionPublicKey(input.ephemeralPublicKey);
  if (!input.iv || !input.ciphertext || input.ciphertext.length > MAX_CIPHERTEXT_CHARS) {
    throw new RelayError("Enveloppe chiffrée invalide ou trop volumineuse.", 400);
  }

  checkSendRate(sender.canonicalAddress);
  pruneQueue(recipient.canonicalAddress);
  const queue = state.queues.get(recipient.canonicalAddress) ?? [];
  const existing = queue.find(
    (item) => item.from === sender.canonicalAddress && item.clientMessageId === clientMessageId,
  );
  if (existing) return { id: existing.id, queuedAt: existing.createdAt, duplicate: true };
  if (queue.length >= MAX_QUEUE) throw new RelayError("File d’attente du destinataire saturée.", 507);

  const envelope: RelayEnvelope = {
    id: randomUUID(),
    clientMessageId,
    from: sender.canonicalAddress,
    to: recipient.canonicalAddress,
    ciphertext: input.ciphertext,
    iv: input.iv,
    ephemeralPublicKey: input.ephemeralPublicKey,
    createdAt: new Date().toISOString(),
  };
  queue.push(envelope);
  state.queues.set(recipient.canonicalAddress, queue);
  return { id: envelope.id, queuedAt: envelope.createdAt, duplicate: false };
}

export function pullEnvelopes(locatorInput: string, authToken: string | null) {
  const identity = authenticate(locatorInput, authToken);
  pruneQueue(identity.canonicalAddress);
  return (state.queues.get(identity.canonicalAddress) ?? []).slice(0, 100);
}

export function acknowledgeEnvelopes(locatorInput: string, authToken: string | null, ids: string[]) {
  const identity = authenticate(locatorInput, authToken);
  const idSet = new Set(ids.filter((id) => typeof id === "string" && id.length <= 100));
  const queue = state.queues.get(identity.canonicalAddress) ?? [];
  const acknowledged = queue.filter((item) => idSet.has(item.id));
  const next = queue.filter((item) => !idSet.has(item.id));

  for (const envelope of acknowledged) {
    const senderCanonical = envelope.from;
    pruneReceipts(senderCanonical);
    const receipts = state.receipts.get(senderCanonical) ?? [];
    const duplicate = receipts.some(
      (receipt) => receipt.clientMessageId === envelope.clientMessageId && receipt.to === envelope.to,
    );
    if (!duplicate && receipts.length < MAX_RECEIPTS) {
      receipts.push({
        id: randomUUID(),
        clientMessageId: envelope.clientMessageId,
        from: envelope.from,
        to: envelope.to,
        deliveredAt: new Date().toISOString(),
      });
      state.receipts.set(senderCanonical, receipts);
    }
  }

  if (next.length) state.queues.set(identity.canonicalAddress, next);
  else state.queues.delete(identity.canonicalAddress);
  return { acknowledged: acknowledged.length };
}

export function pullReceipts(locatorInput: string, authToken: string | null) {
  const identity = authenticate(locatorInput, authToken);
  pruneReceipts(identity.canonicalAddress);
  return (state.receipts.get(identity.canonicalAddress) ?? []).slice(0, 100);
}

export function acknowledgeReceipts(locatorInput: string, authToken: string | null, ids: string[]) {
  const identity = authenticate(locatorInput, authToken);
  const idSet = new Set(ids.filter((id) => typeof id === "string" && id.length <= 100));
  const receipts = state.receipts.get(identity.canonicalAddress) ?? [];
  const next = receipts.filter((item) => !idSet.has(item.id));
  if (next.length) state.receipts.set(identity.canonicalAddress, next);
  else state.receipts.delete(identity.canonicalAddress);
  return { acknowledged: receipts.length - next.length };
}
