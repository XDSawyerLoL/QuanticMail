import { createPublicKey, verify } from "node:crypto";

import {
  canonicalPortableEnvelopeText,
  validatePortableEnvelopeShape,
} from "./federation-core.mjs";
import { assertVerifiedManifest } from "./manifest-node.mjs";

function verifyP256(publicKey, text, signature) {
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

export function verifyPortableEnvelope(
  envelope,
  senderIdentityManifest,
  senderCryptoProfile = null,
  nowMs = Date.now(),
) {
  const value = validatePortableEnvelopeShape(envelope);
  const manifest = assertVerifiedManifest(senderIdentityManifest);
  const payload = manifest.payload;

  if (value.from !== payload.canonicalAddress) {
    throw new Error("L’identité expéditrice de l’enveloppe ne correspond pas au manifeste.");
  }
  if (Date.parse(value.expiresAt) <= nowMs) {
    throw new Error("Enveloppe Quantic expirée.");
  }
  if (Date.parse(value.createdAt) > nowMs + 5 * 60 * 1000) {
    throw new Error("Date de création d’enveloppe Quantic future invalide.");
  }

  const revocation = payload.revocations.find((item) => item.deviceId === value.fromDeviceId);
  if (revocation) {
    throw new Error("Appareil expéditeur Quantic révoqué.");
  }
  const device = payload.devices.find((item) => item.deviceId === value.fromDeviceId);
  if (!device) {
    throw new Error("Appareil expéditeur Quantic inconnu.");
  }

  if (
    !verifyP256(
      device.deviceSigningPublicKey,
      canonicalPortableEnvelopeText(value),
      value.signatures.p256Device,
    )
  ) {
    throw new Error("Signature P-256 de l’enveloppe Quantic invalide.");
  }

  // Crypto V2 enforcement is intentionally deferred to the dedicated PQC tranche.
  // Federation V1 accepts the profile only as future verification context.
  void senderCryptoProfile;

  return value;
}
