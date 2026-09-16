import { createHash, randomUUID, timingSafeEqual } from "node:crypto";

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
  publicKey: QuanticPublicKey;
  authTokenHash: string;
  createdAt: string;
  updatedAt: string;
};

type RelayState = {
  identities: Map<string, IdentityRecord>;
  queues: Map<string, RelayEnvelope[]>;
  receipts: Map<string, DeliveryReceipt[]>;
  sendWindows: Map<string, number[]>;
};

declare global {
  var __quanticRelayState: RelayState | undefined;
}

const state: RelayState =
  globalThis.__quanticRelayState ?? {
    identities: new Map(),
    queues: new Map(),
    receipts: new Map(),
    sendWindows: new Map(),
  };

if (!state.receipts) state.receipts = new Map();
globalThis.__quanticRelayState = state;

const HANDLE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const CLIENT_MESSAGE_ID = /^[a-zA-Z0-9._:-]{8,100}$/;
const MAX_QUEUE = 500;
const MAX_RECEIPTS = 500;
const MAX_CIPHERTEXT_CHARS = 400_000;
const MESSAGE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const SENDS_PER_MINUTE = 60;

export class RelayError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

export function normalizeHandle(value: string) {
  return value.trim().toLowerCase().replace(/@quantic$/i, "");
}

function ensureHandle(value: string) {
  const handle = normalizeHandle(value);
  if (!HANDLE.test(handle)) {
    throw new RelayError(
      "Identifiant invalide. Utilisez 3 à 32 caractères: lettres minuscules, chiffres, point, tiret ou underscore.",
      400,
    );
  }
  return handle;
}

function ensureClientMessageId(value: string) {
  const id = value.trim();
  if (!CLIENT_MESSAGE_ID.test(id)) {
    throw new RelayError("Identifiant de message invalide.", 400);
  }
  return id;
}

function tokenHash(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

function tokenMatches(expectedHash: string, token: string) {
  const actual = Buffer.from(tokenHash(token), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function validatePublicKey(key: QuanticPublicKey) {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new RelayError("Clé publique Quantic invalide.", 400);
  }
}

function pruneQueue(handle: string) {
  const queue = state.queues.get(handle);
  if (!queue) return;
  const cutoff = Date.now() - MESSAGE_TTL_MS;
  const fresh = queue.filter((item) => Date.parse(item.createdAt) >= cutoff);
  if (fresh.length) state.queues.set(handle, fresh);
  else state.queues.delete(handle);
}

function pruneReceipts(handle: string) {
  const receipts = state.receipts.get(handle);
  if (!receipts) return;
  const cutoff = Date.now() - MESSAGE_TTL_MS;
  const fresh = receipts.filter((item) => Date.parse(item.deliveredAt) >= cutoff);
  if (fresh.length) state.receipts.set(handle, fresh);
  else state.receipts.delete(handle);
}

function checkSendRate(handle: string) {
  const now = Date.now();
  const cutoff = now - 60_000;
  const recent = (state.sendWindows.get(handle) ?? []).filter((stamp) => stamp >= cutoff);
  if (recent.length >= SENDS_PER_MINUTE) {
    throw new RelayError("Trop d’envois. Réessayez dans une minute.", 429);
  }
  recent.push(now);
  state.sendWindows.set(handle, recent);
}

export function registerIdentity(input: {
  handle: string;
  publicKey: QuanticPublicKey;
  authToken: string;
}) {
  const handle = ensureHandle(input.handle);
  validatePublicKey(input.publicKey);
  if (input.authToken.length < 40) {
    throw new RelayError("Jeton d’appareil invalide.", 400);
  }

  const existing = state.identities.get(handle);
  const now = new Date().toISOString();

  if (existing && !tokenMatches(existing.authTokenHash, input.authToken)) {
    throw new RelayError(`${handle}@quantic est déjà réservé.`, 409);
  }

  state.identities.set(handle, {
    handle,
    publicKey: input.publicKey,
    authTokenHash: tokenHash(input.authToken),
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  });

  return { address: `${handle}@quantic`, publicKey: input.publicKey };
}

export function authenticate(handleInput: string, authToken: string | null) {
  const handle = ensureHandle(handleInput);
  const identity = state.identities.get(handle);
  if (!identity || !authToken || !tokenMatches(identity.authTokenHash, authToken)) {
    throw new RelayError("Authentification Quantic invalide.", 401);
  }
  return identity;
}

export function resolveIdentity(handleInput: string) {
  const handle = ensureHandle(handleInput);
  const identity = state.identities.get(handle);
  if (!identity) throw new RelayError(`${handle}@quantic est introuvable.`, 404);
  return { address: `${handle}@quantic`, publicKey: identity.publicKey };
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
  const recipientHandle = ensureHandle(input.to);
  const clientMessageId = ensureClientMessageId(input.clientMessageId);
  validatePublicKey(input.ephemeralPublicKey);
  if (!input.iv || !input.ciphertext || input.ciphertext.length > MAX_CIPHERTEXT_CHARS) {
    throw new RelayError("Enveloppe chiffrée invalide ou trop volumineuse.", 400);
  }

  checkSendRate(sender.handle);
  pruneQueue(recipientHandle);
  const queue = state.queues.get(recipientHandle) ?? [];
  const existing = queue.find(
    (item) => item.from === `${sender.handle}@quantic` && item.clientMessageId === clientMessageId,
  );
  if (existing) {
    return { id: existing.id, queuedAt: existing.createdAt, duplicate: true };
  }
  if (queue.length >= MAX_QUEUE) {
    throw new RelayError("File d’attente du destinataire saturée.", 507);
  }

  const envelope: RelayEnvelope = {
    id: randomUUID(),
    clientMessageId,
    from: `${sender.handle}@quantic`,
    to: `${recipientHandle}@quantic`,
    ciphertext: input.ciphertext,
    iv: input.iv,
    ephemeralPublicKey: input.ephemeralPublicKey,
    createdAt: new Date().toISOString(),
  };

  queue.push(envelope);
  state.queues.set(recipientHandle, queue);
  return { id: envelope.id, queuedAt: envelope.createdAt, duplicate: false };
}

export function pullEnvelopes(handleInput: string, authToken: string | null) {
  const identity = authenticate(handleInput, authToken);
  pruneQueue(identity.handle);
  return (state.queues.get(identity.handle) ?? []).slice(0, 100);
}

export function acknowledgeEnvelopes(
  handleInput: string,
  authToken: string | null,
  ids: string[],
) {
  const identity = authenticate(handleInput, authToken);
  const idSet = new Set(ids.filter((id) => typeof id === "string" && id.length <= 100));
  const queue = state.queues.get(identity.handle) ?? [];
  const acknowledged = queue.filter((item) => idSet.has(item.id));
  const next = queue.filter((item) => !idSet.has(item.id));

  for (const envelope of acknowledged) {
    const senderHandle = normalizeHandle(envelope.from);
    pruneReceipts(senderHandle);
    const receipts = state.receipts.get(senderHandle) ?? [];
    const alreadyRecorded = receipts.some(
      (receipt) =>
        receipt.clientMessageId === envelope.clientMessageId && receipt.to === envelope.to,
    );
    if (!alreadyRecorded && receipts.length < MAX_RECEIPTS) {
      receipts.push({
        id: randomUUID(),
        clientMessageId: envelope.clientMessageId,
        from: envelope.from,
        to: envelope.to,
        deliveredAt: new Date().toISOString(),
      });
      state.receipts.set(senderHandle, receipts);
    }
  }

  if (next.length) state.queues.set(identity.handle, next);
  else state.queues.delete(identity.handle);
  return { acknowledged: acknowledged.length };
}

export function pullReceipts(handleInput: string, authToken: string | null) {
  const identity = authenticate(handleInput, authToken);
  pruneReceipts(identity.handle);
  return (state.receipts.get(identity.handle) ?? []).slice(0, 100);
}

export function acknowledgeReceipts(
  handleInput: string,
  authToken: string | null,
  ids: string[],
) {
  const identity = authenticate(handleInput, authToken);
  const idSet = new Set(ids.filter((id) => typeof id === "string" && id.length <= 100));
  const receipts = state.receipts.get(identity.handle) ?? [];
  const next = receipts.filter((item) => !idSet.has(item.id));
  if (next.length) state.receipts.set(identity.handle, next);
  else state.receipts.delete(identity.handle);
  return { acknowledged: receipts.length - next.length };
}
