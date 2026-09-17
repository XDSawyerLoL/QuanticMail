import {
  createHash,
  createPublicKey,
  verify,
} from "node:crypto";
import {
  canonicalManifestText,
  validateManifestShape,
} from "./manifest-core.mjs";
import { identityNamesForKey } from "./identity-names.mjs";

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
  const names = identityNamesForKey(
    payload.handle,
    payload.identitySigningPublicKey,
    payload.fingerprint,
  );
  if (names.canonicalAddress !== payload.canonicalAddress) {
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
