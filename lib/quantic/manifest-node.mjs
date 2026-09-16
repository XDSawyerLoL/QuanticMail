import {
  createHash,
  createPublicKey,
  verify,
} from "node:crypto";
import {
  canonicalManifestText,
  validateManifestShape,
} from "./manifest-core.mjs";

function assertEcPublicKey(key, label) {
  if (!key || key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new Error(`${label} invalide.`);
  }
}

export function fingerprintPublicKeyNode(key) {
  assertEcPublicKey(key, "Clé publique");
  return createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex")
    .slice(0, 10);
}

export function deviceIdForPublicKeyNode(key) {
  return `d-${fingerprintPublicKeyNode(key)}`;
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
  const fingerprint = fingerprintPublicKeyNode(payload.identitySigningPublicKey);
  if (fingerprint !== payload.fingerprint) {
    throw new Error("Empreinte de propriété Quantic invalide.");
  }
  const expectedCanonical = `${payload.handle}~${fingerprint}@quantic`;
  if (expectedCanonical !== payload.canonicalAddress) {
    throw new Error("Empreinte et adresse Quantic canonique incohérentes.");
  }
  for (const device of payload.devices) {
    if (deviceIdForPublicKeyNode(device.publicKey) !== device.deviceId) {
      throw new Error(`Identifiant cryptographique de l’appareil ${device.deviceId} invalide.`);
    }
  }
  if (!verifyManifestSignature(manifest)) {
    throw new Error("Signature du manifeste Quantic invalide.");
  }
  return manifest;
}
