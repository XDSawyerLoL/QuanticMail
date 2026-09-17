const CANONICAL_ADDRESS = /^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/;
const DEVICE_ID = /^d-[0-9a-f]{10}$/;
const CLIENT_MESSAGE_ID = /^[a-zA-Z0-9._:-]{8,100}$/;
const RELAY_ID = /^[0-9a-f]{64}$/;
const FEDERATION_ID = /^[A-Za-z0-9._:-]{12,128}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const PREKEY_ID = /^[0-9a-f]{32}$/;
const KEY_MODES = new Set([
  "v1-one-time-prekey",
  "v1-static-fallback",
  "hybrid-one-time-prekey",
  "hybrid-static-fallback",
]);

function assertP256PublicKey(key, label) {
  if (!key || key.kty !== "EC" || key.crv !== "P-256" || typeof key.x !== "string" || !key.x || typeof key.y !== "string" || !key.y) {
    throw new Error(`${label} invalide.`);
  }
}

function orderedP256PublicKey(key) {
  assertP256PublicKey(key, "Clé publique P-256");
  return { kty: "EC", crv: "P-256", x: key.x, y: key.y };
}

function assertIsoDate(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} invalide.`);
  }
}

function assertCanonicalAddress(value, label) {
  if (typeof value !== "string" || !CANONICAL_ADDRESS.test(value)) {
    throw new Error(`${label} invalide.`);
  }
}

function assertHttpEndpoint(value) {
  if (typeof value !== "string" || value.length > 2048) throw new Error("Endpoint de relais invalide.");
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Endpoint de relais invalide.");
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    throw new Error("Endpoint de relais HTTPS requis hors localhost.");
  }
  if (url.username || url.password || url.search || url.hash) throw new Error("Endpoint de relais non canonique.");
}

function orderedRelay(relay) {
  return {
    relayId: relay.relayId,
    endpoint: relay.endpoint,
    priority: relay.priority,
    protocols: [...relay.protocols].sort(),
    classicalSigningPublicKey: orderedP256PublicKey(relay.classicalSigningPublicKey),
    ...(relay.postQuantumSigningPublicKeySpki ? { postQuantumSigningPublicKeySpki: relay.postQuantumSigningPublicKeySpki } : {}),
    expiresAt: relay.expiresAt,
  };
}

export function canonicalPortableEnvelopeText(envelope) {
  const value = validatePortableEnvelopeShape(envelope);
  const canonical = {
    format: value.format,
    version: value.version,
    clientMessageId: value.clientMessageId,
    from: value.from,
    fromDeviceId: value.fromDeviceId,
    to: value.to,
    toDeviceId: value.toDeviceId,
    keyMode: value.keyMode,
    cryptoSuite: value.cryptoSuite,
    ...(value.preKeyId ? { preKeyId: value.preKeyId } : {}),
    ...(value.classicalEphemeralPublicKey
      ? { classicalEphemeralPublicKey: orderedP256PublicKey(value.classicalEphemeralPublicKey) }
      : {}),
    ...(value.pqKemCiphertext ? { pqKemCiphertext: value.pqKemCiphertext } : {}),
    iv: value.iv,
    ciphertext: value.ciphertext,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
  };
  return JSON.stringify(canonical);
}

export function canonicalRouteManifestText(payload) {
  const manifest = validateRouteManifestShape({
    format: "quantic-route-manifest",
    version: 1,
    payload,
    signatures: { p256: "validation-placeholder" },
  });
  const value = manifest.payload;
  const relays = [...value.relays]
    .sort((a, b) => a.priority - b.priority || a.relayId.localeCompare(b.relayId) || a.endpoint.localeCompare(b.endpoint))
    .map(orderedRelay);
  return JSON.stringify({
    version: value.version,
    sequence: value.sequence,
    canonicalAddress: value.canonicalAddress,
    identitySigningPublicKey: orderedP256PublicKey(value.identitySigningPublicKey),
    identityManifestSequence: value.identityManifestSequence,
    cryptoProfileSequence: value.cryptoProfileSequence,
    cryptoProfileDigest: value.cryptoProfileDigest,
    relays,
    issuedAt: value.issuedAt,
    expiresAt: value.expiresAt,
  });
}

export function canonicalFederationReceiptText(payload) {
  const receipt = validateFederationReceiptShape({
    format: "quantic-federation-receipt",
    version: 1,
    payload,
    p256Signature: "validation-placeholder",
  });
  const value = receipt.payload;
  return JSON.stringify({
    version: value.version,
    federationId: value.federationId,
    envelopeDigest: value.envelopeDigest,
    clientMessageId: value.clientMessageId,
    from: value.from,
    fromDeviceId: value.fromDeviceId,
    to: value.to,
    toDeviceId: value.toDeviceId,
    destinationRelayId: value.destinationRelayId,
    routeSequence: value.routeSequence,
    deliveredAt: value.deliveredAt,
    expiresAt: value.expiresAt,
  });
}

export async function envelopeDigest(envelope) {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalPortableEnvelopeText(envelope)),
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function validatePortableEnvelopeShape(envelope) {
  if (!envelope || envelope.format !== "quantic-envelope" || envelope.version !== 2) {
    throw new Error("Format d’enveloppe Quantic invalide.");
  }
  assertCanonicalAddress(envelope.from, "Adresse expéditeur");
  assertCanonicalAddress(envelope.to, "Adresse destinataire");
  if (typeof envelope.fromDeviceId !== "string" || !DEVICE_ID.test(envelope.fromDeviceId)) {
    throw new Error("Appareil expéditeur invalide.");
  }
  if (typeof envelope.toDeviceId !== "string" || !DEVICE_ID.test(envelope.toDeviceId)) {
    throw new Error("Appareil destinataire invalide.");
  }
  if (typeof envelope.clientMessageId !== "string" || !CLIENT_MESSAGE_ID.test(envelope.clientMessageId)) {
    throw new Error("Identifiant de message invalide.");
  }
  if (!KEY_MODES.has(envelope.keyMode)) throw new Error("Mode de clé d’enveloppe invalide.");
  if (typeof envelope.cryptoSuite !== "string" || envelope.cryptoSuite.length < 3 || envelope.cryptoSuite.length > 128) {
    throw new Error("Suite cryptographique invalide.");
  }
  if (envelope.preKeyId !== undefined && (typeof envelope.preKeyId !== "string" || !PREKEY_ID.test(envelope.preKeyId))) {
    throw new Error("Identifiant de prekey invalide.");
  }
  if (envelope.classicalEphemeralPublicKey !== undefined) {
    assertP256PublicKey(envelope.classicalEphemeralPublicKey, "Clé éphémère classique");
  }
  if (envelope.pqKemCiphertext !== undefined && (typeof envelope.pqKemCiphertext !== "string" || !envelope.pqKemCiphertext)) {
    throw new Error("Ciphertext KEM post-quantique invalide.");
  }
  if (typeof envelope.iv !== "string" || !envelope.iv) throw new Error("IV d’enveloppe invalide.");
  if (typeof envelope.ciphertext !== "string" || !envelope.ciphertext || envelope.ciphertext.length > 400_000) {
    throw new Error("Ciphertext d’enveloppe invalide.");
  }
  assertIsoDate(envelope.createdAt, "Date de création d’enveloppe");
  assertIsoDate(envelope.expiresAt, "Date d’expiration d’enveloppe");
  if (Date.parse(envelope.expiresAt) <= Date.parse(envelope.createdAt)) {
    throw new Error("Expiration d’enveloppe invalide.");
  }
  if (!envelope.signatures || typeof envelope.signatures.p256Device !== "string" || !envelope.signatures.p256Device) {
    throw new Error("Signature P-256 d’enveloppe absente.");
  }
  if (envelope.signatures.mlDsa65Device !== undefined && typeof envelope.signatures.mlDsa65Device !== "string") {
    throw new Error("Signature ML-DSA d’enveloppe invalide.");
  }
  return envelope;
}

export function validateRouteManifestShape(manifest) {
  if (!manifest || manifest.format !== "quantic-route-manifest" || manifest.version !== 1) {
    throw new Error("Format de Route Manifest Quantic invalide.");
  }
  const payload = manifest.payload;
  if (!payload || payload.version !== 1) throw new Error("Version de Route Manifest Quantic invalide.");
  if (!Number.isSafeInteger(payload.sequence) || payload.sequence < 1) throw new Error("Séquence de Route Manifest invalide.");
  assertCanonicalAddress(payload.canonicalAddress, "Adresse canonique de route");
  assertP256PublicKey(payload.identitySigningPublicKey, "Clé de propriété de route");
  if (!Number.isSafeInteger(payload.identityManifestSequence) || payload.identityManifestSequence < 1) {
    throw new Error("Séquence d’Identity Manifest de route invalide.");
  }
  if (payload.cryptoProfileSequence !== null && (!Number.isSafeInteger(payload.cryptoProfileSequence) || payload.cryptoProfileSequence < 1)) {
    throw new Error("Séquence de Crypto Profile invalide.");
  }
  if (payload.cryptoProfileSequence === null && payload.cryptoProfileDigest !== null) {
    throw new Error("Digest de Crypto Profile sans séquence.");
  }
  if (payload.cryptoProfileSequence !== null && (typeof payload.cryptoProfileDigest !== "string" || !/^[0-9a-f]{64}$/.test(payload.cryptoProfileDigest))) {
    throw new Error("Digest de Crypto Profile invalide.");
  }
  if (!Array.isArray(payload.relays) || payload.relays.length === 0 || payload.relays.length > 16) {
    throw new Error("Liste de relais de route invalide.");
  }
  const relayIds = new Set();
  for (const relay of payload.relays) {
    if (!relay || typeof relay.relayId !== "string" || !RELAY_ID.test(relay.relayId)) throw new Error("Identité de relais invalide.");
    if (relayIds.has(relay.relayId)) throw new Error("Relais dupliqué dans le Route Manifest.");
    relayIds.add(relay.relayId);
    assertHttpEndpoint(relay.endpoint);
    if (!Number.isSafeInteger(relay.priority) || relay.priority < 0 || relay.priority > 65535) throw new Error("Priorité de relais invalide.");
    if (!Array.isArray(relay.protocols) || relay.protocols.length === 0 || relay.protocols.some((item) => typeof item !== "string" || !item || item.length > 64)) {
      throw new Error("Protocoles de relais invalides.");
    }
    assertP256PublicKey(relay.classicalSigningPublicKey, "Clé publique de relais");
    if (relay.postQuantumSigningPublicKeySpki !== undefined && (typeof relay.postQuantumSigningPublicKeySpki !== "string" || !relay.postQuantumSigningPublicKeySpki)) {
      throw new Error("Clé publique post-quantique de relais invalide.");
    }
    assertIsoDate(relay.expiresAt, "Date d’expiration de relais");
  }
  assertIsoDate(payload.issuedAt, "Date d’émission de route");
  assertIsoDate(payload.expiresAt, "Date d’expiration de route");
  if (Date.parse(payload.expiresAt) <= Date.parse(payload.issuedAt)) throw new Error("Expiration de route invalide.");
  if (!manifest.signatures || typeof manifest.signatures.p256 !== "string" || !manifest.signatures.p256) {
    throw new Error("Signature P-256 de Route Manifest absente.");
  }
  if (manifest.signatures.mlDsa65 !== undefined && typeof manifest.signatures.mlDsa65 !== "string") {
    throw new Error("Signature ML-DSA de Route Manifest invalide.");
  }
  return manifest;
}

export function validateFederationReceiptShape(receipt) {
  if (!receipt || receipt.format !== "quantic-federation-receipt" || receipt.version !== 1) {
    throw new Error("Format de reçu de fédération Quantic invalide.");
  }
  const payload = receipt.payload;
  if (!payload || payload.version !== 1) throw new Error("Version de reçu de fédération invalide.");
  if (typeof payload.federationId !== "string" || !FEDERATION_ID.test(payload.federationId)) {
    throw new Error("Identifiant de fédération du reçu invalide.");
  }
  if (typeof payload.envelopeDigest !== "string" || !SHA256_HEX.test(payload.envelopeDigest)) {
    throw new Error("Digest d’enveloppe du reçu invalide.");
  }
  if (typeof payload.clientMessageId !== "string" || !CLIENT_MESSAGE_ID.test(payload.clientMessageId)) {
    throw new Error("Identifiant de message du reçu invalide.");
  }
  assertCanonicalAddress(payload.from, "Adresse expéditeur du reçu");
  assertCanonicalAddress(payload.to, "Adresse destinataire du reçu");
  if (typeof payload.fromDeviceId !== "string" || !DEVICE_ID.test(payload.fromDeviceId)) {
    throw new Error("Appareil expéditeur du reçu invalide.");
  }
  if (typeof payload.toDeviceId !== "string" || !DEVICE_ID.test(payload.toDeviceId)) {
    throw new Error("Appareil destinataire du reçu invalide.");
  }
  if (typeof payload.destinationRelayId !== "string" || !RELAY_ID.test(payload.destinationRelayId)) {
    throw new Error("Relay ID du reçu invalide.");
  }
  if (!Number.isSafeInteger(payload.routeSequence) || payload.routeSequence < 1) {
    throw new Error("Séquence de route du reçu invalide.");
  }
  assertIsoDate(payload.deliveredAt, "Date de livraison du reçu");
  assertIsoDate(payload.expiresAt, "Expiration du reçu");
  if (Date.parse(payload.expiresAt) <= Date.parse(payload.deliveredAt)) {
    throw new Error("Expiration du reçu invalide.");
  }
  if (typeof receipt.p256Signature !== "string" || !receipt.p256Signature) {
    throw new Error("Signature P-256 du reçu absente.");
  }
  return receipt;
}
