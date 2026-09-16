import {
  createHash,
  createPublicKey,
  verify,
} from "node:crypto";
import {
  assertDeviceIdMatchesDigest,
  deviceIdFromDigestHex,
} from "./device-id-core.mjs";
import {
  canonicalManifestText,
  validateManifestShape,
} from "./manifest-core.mjs";

function assertEcPublicKey(key, label) {
  if (!key || key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new Error(`${label} invalide.`);
  }
}

function publicKeyDigestHex(key) {
  assertEcPublicKey(key, "Clé publique");
  return createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex");
}

export function fingerprintPublicKeyNode(key, length = 10) {
  if (length !== 10 && length !== 32) throw new Error("Longueur d’empreinte Quantic invalide.");
  return publicKeyDigestHex(key).slice(0, length);
}

export function deviceIdForPublicKeyNode(key, length = 10) {
  return deviceIdFromDigestHex(publicKeyDigestHex(key), length);
}

export function verifyManifestSignature(manifest) {
  try {
    const payload = validateManifestShape(manifest);
    return verify(
      "sha256",
      Buffer.from(canonicalManifestText(payload), "utf8"),
      {
        key: createPublicKey({ key: payload.identitySigningPublicKey, format: "jwk" }),
        dsaEncoding: "ieee-p1363",
      },
      Buffer.from(manifest.signature, "base64"),
    );
  } catch {
    return false;
  }
}

export function assertVerifiedManifest(manifest) {
  const payload = validateManifestShape(manifest);
  const fingerprintLength = payload.fingerprint.length;
  const fingerprint = fingerprintPublicKeyNode(payload.identitySigningPublicKey, fingerprintLength);
  if (fingerprint !== payload.fingerprint) {
    throw new Error("Empreinte de propriété Quantic invalide.");
  }
  const expectedCanonical = `${payload.handle}~${fingerprint}@quantic`;
  if (expectedCanonical !== payload.canonicalAddress) {
    throw new Error("Empreinte et adresse Quantic canonique incohérentes.");
  }
  for (const device of payload.devices) {
    try {
      assertDeviceIdMatchesDigest(device.deviceId, publicKeyDigestHex(device.publicKey));
    } catch {
      throw new Error(`Identifiant cryptographique de l’appareil ${device.deviceId} invalide.`);
    }
  }
  if (!verifyManifestSignature(manifest)) {
    throw new Error("Signature du manifeste Quantic invalide.");
  }
  return manifest;
}
