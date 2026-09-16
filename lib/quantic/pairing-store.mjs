import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const DEFAULT_TTL_MS = 10 * 60 * 1000;
const MAX_PACKAGE_BYTES = 4 * 1024 * 1024;

function hashSecret(secret) {
  return createHash("sha256").update(String(secret), "utf8").digest();
}

function assertSecret(invite, secret) {
  const actual = hashSecret(secret);
  if (actual.length !== invite.secretHash.length || !timingSafeEqual(actual, invite.secretHash)) {
    throw new Error("Secret de pairing invalide.");
  }
}

function getInvite(store, inviteId, now) {
  const invite = store.invites.get(inviteId);
  if (!invite) throw new Error("Invitation de pairing introuvable ou consommée.");
  if (invite.expiresAt <= now) {
    store.invites.delete(inviteId);
    throw new Error("Invitation de pairing expirée.");
  }
  return invite;
}

export function createPairingStore() {
  return { invites: new Map() };
}

export function createInvite(store, root, secret, now = Date.now(), ttlMs = DEFAULT_TTL_MS) {
  if (!root?.canonicalAddress || !root?.rootDeviceId) throw new Error("Appareil maître invalide.");
  if (!secret || String(secret).length < 16) throw new Error("Secret de pairing invalide.");
  const inviteId = randomBytes(16).toString("hex");
  const expiresAt = now + ttlMs;
  store.invites.set(inviteId, {
    inviteId,
    canonicalAddress: root.canonicalAddress,
    rootDeviceId: root.rootDeviceId,
    secretHash: hashSecret(secret),
    createdAt: now,
    expiresAt,
    request: null,
    package: null,
  });
  return { inviteId, expiresAt };
}

export function submitPairingRequest(store, inviteId, secret, request, now = Date.now()) {
  const invite = getInvite(store, inviteId, now);
  assertSecret(invite, secret);
  if (!request || typeof request !== "object") throw new Error("Demande de pairing invalide.");
  invite.request = request;
  return { accepted: true, expiresAt: invite.expiresAt };
}

export function getPairingRequest(store, inviteId, secret, now = Date.now()) {
  const invite = getInvite(store, inviteId, now);
  assertSecret(invite, secret);
  return invite.request;
}

export function attachPairingPackage(store, inviteId, secret, encryptedPackage, now = Date.now()) {
  const invite = getInvite(store, inviteId, now);
  assertSecret(invite, secret);
  if (!invite.request) throw new Error("Aucune demande de pairing à approuver.");
  const size = Buffer.byteLength(JSON.stringify(encryptedPackage), "utf8");
  if (size > MAX_PACKAGE_BYTES) throw new Error("Paquet de pairing trop volumineux.");
  invite.package = encryptedPackage;
  return { stored: true, bytes: size, expiresAt: invite.expiresAt };
}

export function takePairingPackage(store, inviteId, secret, now = Date.now()) {
  const invite = getInvite(store, inviteId, now);
  assertSecret(invite, secret);
  if (!invite.package) throw new Error("Paquet de pairing introuvable.");
  const encryptedPackage = invite.package;
  store.invites.delete(inviteId);
  return encryptedPackage;
}

export function pairingStatus(store, inviteId, secret, now = Date.now()) {
  const invite = getInvite(store, inviteId, now);
  assertSecret(invite, secret);
  return {
    inviteId,
    canonicalAddress: invite.canonicalAddress,
    rootDeviceId: invite.rootDeviceId,
    expiresAt: invite.expiresAt,
    hasRequest: Boolean(invite.request),
    hasPackage: Boolean(invite.package),
  };
}
