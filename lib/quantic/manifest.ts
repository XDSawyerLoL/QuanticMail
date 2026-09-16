import { fingerprintPublicKey, signChallenge } from "@/lib/quantic/crypto";
import { deviceIdFromPublicKey, verifyTextSignature } from "@/lib/quantic/device";
import type { DeviceCertificate, LocalIdentity } from "@/lib/quantic/local-db";
import { canonicalManifestText } from "@/lib/quantic/manifest-core.mjs";
import type {
  QuanticIdentityManifest,
  QuanticIdentityManifestPayload,
  QuanticManifestDevice,
  QuanticRevocation,
} from "@/lib/quantic/manifest-types";

function samePoint(a: JsonWebKey, b: JsonWebKey) {
  return a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;
}

async function rootDevice(identity: LocalIdentity): Promise<QuanticManifestDevice> {
  if (!identity.signingPublicKey) throw new Error("Clé publique de propriété Quantic absente.");
  const deviceId = identity.deviceId ?? (await deviceIdFromPublicKey(identity.publicKey));
  return {
    deviceId,
    label: identity.deviceLabel ?? "Appareil principal",
    publicKey: identity.publicKey,
    deviceSigningPublicKey: identity.deviceSigningPublicKey ?? identity.signingPublicKey,
    kind: "root",
    issuedAt: identity.createdAt,
  };
}

export async function signManifestPayload(
  identity: LocalIdentity,
  payload: QuanticIdentityManifestPayload,
): Promise<QuanticIdentityManifest> {
  if (!identity.signingPrivateKey) throw new Error("Clé maîtresse privée absente.");
  const signature = await signChallenge(identity.signingPrivateKey, canonicalManifestText(payload));
  return {
    format: "quantic-identity-manifest",
    version: 1,
    payload,
    signature,
  };
}

export async function createInitialManifest(identity: LocalIdentity): Promise<QuanticIdentityManifest> {
  if (!identity.canonicalAddress || !identity.fingerprint || !identity.signingPublicKey) {
    throw new Error("Identité Quantic canonique incomplète.");
  }
  const now = new Date().toISOString();
  return signManifestPayload(identity, {
    version: 1,
    sequence: 1,
    canonicalAddress: identity.canonicalAddress,
    handle: identity.handle,
    fingerprint: identity.fingerprint,
    identityPublicKey: identity.publicKey,
    identitySigningPublicKey: identity.signingPublicKey,
    devices: [await rootDevice(identity)],
    revocations: [],
    issuedAt: now,
  });
}

export async function verifyManifestBrowser(manifest: QuanticIdentityManifest) {
  const payload = manifest.payload;
  if (manifest.format !== "quantic-identity-manifest" || manifest.version !== 1 || payload.version !== 1) return false;
  const fingerprint = await fingerprintPublicKey(payload.identitySigningPublicKey);
  if (fingerprint !== payload.fingerprint) return false;
  if (`${payload.handle}~${fingerprint}@quantic` !== payload.canonicalAddress) return false;
  const roots = payload.devices.filter((device) => device.kind === "root");
  if (roots.length !== 1) return false;
  const revoked = new Set(payload.revocations.map((item) => item.deviceId));
  if (payload.devices.some((device) => revoked.has(device.deviceId))) return false;
  for (const device of payload.devices) {
    if ((await deviceIdFromPublicKey(device.publicKey)) !== device.deviceId) return false;
  }
  return verifyTextSignature(
    payload.identitySigningPublicKey,
    canonicalManifestText(payload),
    manifest.signature,
  );
}

export async function addDeviceToManifest(
  identity: LocalIdentity,
  current: QuanticIdentityManifest,
  certificate: DeviceCertificate,
): Promise<QuanticIdentityManifest> {
  if (!identity.canonicalAddress || identity.role === "secondary") {
    throw new Error("Seul l’appareil maître peut modifier le manifeste.");
  }
  if (certificate.payload.canonicalAddress !== current.payload.canonicalAddress) {
    throw new Error("Le certificat vise une autre identité Quantic.");
  }
  const deviceId = certificate.payload.deviceId;
  if (current.payload.revocations.some((item) => item.deviceId === deviceId)) {
    throw new Error("Un appareil déjà révoqué doit générer de nouvelles clés avant d’être lié à nouveau.");
  }
  const devices = current.payload.devices.filter((item) => item.deviceId !== deviceId);
  devices.push({
    deviceId,
    label: certificate.payload.deviceLabel,
    publicKey: certificate.payload.devicePublicKey,
    deviceSigningPublicKey: certificate.payload.deviceSigningPublicKey,
    kind: "linked",
    issuedAt: certificate.payload.issuedAt,
  });
  return signManifestPayload(identity, {
    ...current.payload,
    sequence: current.payload.sequence + 1,
    devices,
    issuedAt: new Date().toISOString(),
  });
}

export async function revokeDeviceInManifest(
  identity: LocalIdentity,
  current: QuanticIdentityManifest,
  deviceId: string,
  reason: QuanticRevocation["reason"] = "user",
): Promise<QuanticIdentityManifest> {
  if (!identity.signingPrivateKey || identity.role === "secondary") {
    throw new Error("Seul l’appareil maître peut révoquer un appareil.");
  }
  const target = current.payload.devices.find((item) => item.deviceId === deviceId);
  if (!target) throw new Error("Appareil introuvable dans le manifeste actif.");
  if (target.kind === "root") throw new Error("L’appareil maître ne peut pas être révoqué par cette opération.");
  const revocation: QuanticRevocation = {
    deviceId,
    revokedAt: new Date().toISOString(),
    reason,
  };
  return signManifestPayload(identity, {
    ...current.payload,
    sequence: current.payload.sequence + 1,
    devices: current.payload.devices.filter((item) => item.deviceId !== deviceId),
    revocations: [...current.payload.revocations, revocation],
    issuedAt: revocation.revokedAt,
  });
}

export function sameManifestIdentity(
  manifest: QuanticIdentityManifest,
  canonicalAddress: string,
  signingPublicKey?: JsonWebKey,
) {
  if (manifest.payload.canonicalAddress !== canonicalAddress) return false;
  if (signingPublicKey && !samePoint(manifest.payload.identitySigningPublicKey, signingPublicKey)) return false;
  return true;
}
