const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} invalide.`);
  }
  return value;
}

function requirePositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${label} invalide.`);
  return value;
}

function requireIsoDate(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) throw new Error(`${label} invalide.`);
  return value;
}

function requireP256PublicJwk(value, label) {
  const key = requireObject(value, label);
  if (
    key.kty !== "EC" ||
    key.crv !== "P-256" ||
    typeof key.x !== "string" ||
    typeof key.y !== "string" ||
    !key.x ||
    !key.y ||
    "d" in key
  ) {
    throw new Error(`${label} invalide.`);
  }
  return key;
}

function requireBase64url(value, label) {
  if (typeof value !== "string" || value.length < 16 || !BASE64URL_RE.test(value)) {
    throw new Error(`${label} invalide.`);
  }
  return value;
}

function requireBase64(value, label) {
  if (typeof value !== "string" || value.length < 16 || !BASE64_RE.test(value)) {
    throw new Error(`${label} invalide.`);
  }
  return value;
}

function canonicalDevice(device) {
  const record = requireObject(device, "Appareil Crypto V2");
  if (typeof record.deviceId !== "string" || !/^d-[0-9a-f]{10}$/.test(record.deviceId)) {
    throw new Error("deviceId Crypto V2 invalide.");
  }
  if (record.mlKemAlgorithm !== "ML-KEM-768") throw new Error("Algorithme ML-KEM Crypto V2 invalide.");
  if (record.mlDsaAlgorithm !== "ML-DSA-65") throw new Error("Algorithme ML-DSA Crypto V2 invalide.");
  return {
    deviceId: record.deviceId,
    mlKemAlgorithm: "ML-KEM-768",
    mlKemPublicKeySpki: requireBase64url(record.mlKemPublicKeySpki, "Clé publique ML-KEM-768"),
    mlDsaAlgorithm: "ML-DSA-65",
    mlDsaPublicKeySpki: requireBase64url(record.mlDsaPublicKeySpki, "Clé publique ML-DSA-65"),
  };
}

export function canonicalCryptoProfilePayload(payload) {
  const record = requireObject(payload, "Payload Crypto Profile V2");
  if (record.version !== 2) throw new Error("Version Crypto Profile V2 invalide.");
  requirePositiveInteger(record.sequence, "Séquence Crypto Profile V2");
  if (typeof record.canonicalAddress !== "string" || !record.canonicalAddress.endsWith("@quantic")) {
    throw new Error("Adresse canonique Crypto V2 invalide.");
  }
  const identitySigningPublicKey = requireP256PublicJwk(record.identitySigningPublicKey, "Clé d’identité P-256");
  requirePositiveInteger(record.identityManifestSequence, "Séquence Identity Manifest");
  if (record.policy !== "transition" && record.policy !== "hybrid-required") {
    throw new Error("Politique Crypto V2 invalide.");
  }
  if (record.identityMlDsaAlgorithm !== "ML-DSA-65") {
    throw new Error("Algorithme de racine ML-DSA invalide.");
  }
  if (!Array.isArray(record.devices) || record.devices.length < 1) {
    throw new Error("Crypto Profile V2 sans appareil.");
  }
  const devices = record.devices.map(canonicalDevice).sort((a, b) => a.deviceId.localeCompare(b.deviceId));
  const ids = new Set();
  for (const device of devices) {
    if (ids.has(device.deviceId)) throw new Error("Appareil Crypto V2 dupliqué.");
    ids.add(device.deviceId);
  }
  return {
    version: 2,
    sequence: record.sequence,
    canonicalAddress: record.canonicalAddress.trim().toLowerCase(),
    identitySigningPublicKey: {
      kty: identitySigningPublicKey.kty,
      crv: identitySigningPublicKey.crv,
      x: identitySigningPublicKey.x,
      y: identitySigningPublicKey.y,
    },
    identityManifestSequence: record.identityManifestSequence,
    policy: record.policy,
    identityMlDsaAlgorithm: "ML-DSA-65",
    identityMlDsaPublicKeySpki: requireBase64url(record.identityMlDsaPublicKeySpki, "Racine publique ML-DSA-65"),
    devices,
    issuedAt: requireIsoDate(record.issuedAt, "issuedAt Crypto Profile V2"),
  };
}

export function canonicalCryptoProfileText(payload) {
  return JSON.stringify(canonicalCryptoProfilePayload(payload));
}

export function validateCryptoProfileShape(profile) {
  const record = requireObject(profile, "Crypto Profile V2");
  if (record.format !== "quantic-crypto-profile" || record.version !== 2) {
    throw new Error("Format Crypto Profile V2 invalide.");
  }
  const payload = canonicalCryptoProfilePayload(record.payload);
  const signatures = requireObject(record.signatures, "Signatures Crypto Profile V2");
  requireBase64(signatures.p256, "Signature P-256 Crypto Profile V2");
  requireBase64url(signatures.mlDsa65Self, "Auto-signature ML-DSA-65 Crypto Profile V2");
  if (signatures.mlDsa65Continuity !== undefined) {
    requireBase64url(signatures.mlDsa65Continuity, "Signature de continuité ML-DSA-65");
  }
  return {
    format: "quantic-crypto-profile",
    version: 2,
    payload,
    signatures: {
      p256: signatures.p256,
      mlDsa65Self: signatures.mlDsa65Self,
      ...(signatures.mlDsa65Continuity ? { mlDsa65Continuity: signatures.mlDsa65Continuity } : {}),
    },
  };
}

export function mergeCryptoProfileState(current, incoming) {
  const next = validateCryptoProfileShape(incoming);
  if (!current) return next;
  const previous = validateCryptoProfileShape(current);
  if (previous.payload.canonicalAddress !== next.payload.canonicalAddress) {
    throw new Error("Conflit d’identité Crypto Profile V2.");
  }
  if (next.payload.sequence < previous.payload.sequence) {
    throw new Error("Crypto Profile rollback refusé : séquence plus ancienne.");
  }
  if (next.payload.sequence === previous.payload.sequence) {
    if (canonicalCryptoProfileText(previous.payload) !== canonicalCryptoProfileText(next.payload)) {
      throw new Error("Conflit/fork Crypto Profile pour la même séquence.");
    }
    return previous;
  }
  if (previous.payload.policy === "hybrid-required" && next.payload.policy !== "hybrid-required") {
    throw new Error("Downgrade Crypto V2 refusé après activation hybrid-required.");
  }
  return next;
}
