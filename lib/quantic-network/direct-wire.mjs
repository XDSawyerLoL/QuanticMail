const DIRECT_FORMAT = "quantic-direct-frame";
const MAX_FRAME_BYTES = 512 * 1024;
const FORBIDDEN_KEYS = new Set([
  "subject",
  "body",
  "plaintext",
  "messagetext",
  "privatekey",
  "private_key",
  "signingprivatekey",
  "deviceprivatekey",
  "mlkemprivatekey",
  "mldsaprivatekey",
  "authtoken",
  "password",
]);

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function assertNoForbiddenMaterial(value, path = "payload") {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      assertNoForbiddenMaterial(value[index], `${path}[${index}]`);
    }
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = key.replace(/[-_]/g, "").toLowerCase();
    if (FORBIDDEN_KEYS.has(key.toLowerCase()) || FORBIDDEN_KEYS.has(normalized)) {
      throw new Error(`Champ plaintext/privé interdit dans le transport direct Quantic: ${path}.${key}`);
    }
    assertNoForbiddenMaterial(nested, `${path}.${key}`);
  }
}

function requireString(value, label, min = 1, max = 4096) {
  if (typeof value !== "string" || value.length < min || value.length > max) {
    throw new Error(`${label} direct Quantic invalide.`);
  }
  return value;
}

function validatePublicKey(value) {
  if (
    !value ||
    typeof value !== "object" ||
    value.kty !== "EC" ||
    value.crv !== "P-256" ||
    typeof value.x !== "string" ||
    typeof value.y !== "string"
  ) {
    throw new Error("Clé publique éphémère directe invalide.");
  }
}

function validateEnvelope(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Enveloppe directe Quantic invalide.");
  }
  assertNoForbiddenMaterial(input);
  requireString(input.id, "Identifiant d’enveloppe", 8, 128);
  requireString(input.clientMessageId, "Identifiant client", 8, 128);
  requireString(input.from, "Expéditeur", 8, 128);
  requireString(input.fromDeviceId, "Appareil expéditeur", 4, 80);
  requireString(input.to, "Destinataire", 8, 128);
  requireString(input.toDeviceId, "Appareil destinataire", 4, 80);
  requireString(input.ciphertext, "Ciphertext", 4, 450_000);
  requireString(input.iv, "IV", 4, 512);
  validatePublicKey(input.ephemeralPublicKey);
  const createdAt = Date.parse(requireString(input.createdAt, "Date", 10, 64));
  if (!Number.isFinite(createdAt)) throw new Error("Date d’enveloppe directe invalide.");
  const serialized = JSON.stringify(input);
  if (Buffer.byteLength(serialized, "utf8") > MAX_FRAME_BYTES) {
    throw new Error("Enveloppe directe Quantic trop volumineuse.");
  }
  return clone(input);
}

function validateReceipt(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Reçu direct Quantic invalide.");
  }
  assertNoForbiddenMaterial(input);
  requireString(input.id, "Identifiant de reçu", 8, 128);
  requireString(input.clientMessageId, "Identifiant client", 8, 128);
  requireString(input.from, "Expéditeur du reçu", 8, 128);
  requireString(input.fromDeviceId, "Appareil du reçu", 4, 80);
  requireString(input.to, "Destinataire du reçu", 8, 128);
  requireString(input.toDeviceId, "Appareil destinataire du reçu", 4, 80);
  if (!Number.isFinite(Date.parse(requireString(input.deliveredAt, "Date de livraison", 10, 64)))) {
    throw new Error("Date de reçu direct invalide.");
  }
  return clone(input);
}

export function createDirectEnvelopeFrame(envelope) {
  return {
    format: DIRECT_FORMAT,
    version: 1,
    type: "envelope",
    payload: validateEnvelope(envelope),
  };
}

export function createDirectReceiptFrame(receipt) {
  return {
    format: DIRECT_FORMAT,
    version: 1,
    type: "receipt",
    payload: validateReceipt(receipt),
  };
}

export function parseDirectFrame(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (Buffer.byteLength(text, "utf8") > MAX_FRAME_BYTES) throw new Error("Trame directe Quantic trop volumineuse.");
  let frame;
  try {
    frame = typeof value === "string" ? JSON.parse(value) : clone(value);
  } catch {
    throw new Error("Trame directe Quantic JSON invalide.");
  }
  if (!frame || frame.format !== DIRECT_FORMAT || frame.version !== 1) {
    throw new Error("Format de trame directe Quantic invalide.");
  }
  if (frame.type === "envelope") return { ...frame, payload: validateEnvelope(frame.payload) };
  if (frame.type === "receipt") return { ...frame, payload: validateReceipt(frame.payload) };
  throw new Error("Type de trame directe Quantic inconnu.");
}
