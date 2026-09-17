import { activeDevices } from "./manifest-core.mjs";
import {
  claimFromPreKeyPool,
  countPreKeyPool,
  publishToPreKeyPool,
} from "./prekey-pool.mjs";
import {
  isPreKeyExpired,
  validatePreKeyRecord,
  verifyPreKeySignature,
  type SignedPreKeyRecord,
} from "./prekey-core.mjs";
import { pullEnvelopes, resolveIdentity, RelayError } from "./relay.ts";
import { readStandaloneManifest } from "./standalone-manifest.ts";
import { getStandalonePreKeyStore } from "./standalone-v11-state.ts";

function poolKey(canonicalAddress: string, deviceId: string) {
  return `${canonicalAddress}#${deviceId}`;
}

function authenticate(locator: string, authToken: string | null, deviceId: string) {
  pullEnvelopes(locator, authToken, deviceId);
  return resolveIdentity(locator);
}

function activeManifestDevice(canonicalAddress: string, deviceId: string) {
  const manifest = readStandaloneManifest(canonicalAddress);
  if (!manifest) {
    throw new RelayError("Les one-time prekeys nécessitent un manifeste V1 actif.", 409);
  }
  const device = activeDevices(manifest).find((item) => item.deviceId === deviceId);
  if (!device) {
    throw new RelayError("Cet appareil n’est plus autorisé par le manifeste Quantic.", 401);
  }
  return device;
}

export async function publishStandalonePreKeys(input: {
  locator: string;
  authToken: string | null;
  deviceId: string;
  records: SignedPreKeyRecord[];
}) {
  const identity = authenticate(input.locator, input.authToken, input.deviceId);
  const device = activeManifestDevice(identity.canonicalAddress, input.deviceId);
  if (!Array.isArray(input.records) || input.records.length > 64) {
    throw new RelayError("Lot de prekeys invalide ou trop volumineux.", 400);
  }

  const valid: SignedPreKeyRecord[] = [];
  for (const record of input.records) {
    try {
      validatePreKeyRecord(record);
    } catch (error) {
      throw new RelayError(error instanceof Error ? error.message : "Prekey invalide.", 400);
    }
    if (record.canonicalAddress !== identity.canonicalAddress || record.deviceId !== input.deviceId) {
      throw new RelayError("La prekey ne correspond pas à l’appareil authentifié.", 400);
    }
    if (isPreKeyExpired(record)) continue;
    if (!(await verifyPreKeySignature(record, device.deviceSigningPublicKey))) {
      throw new RelayError("Signature de prekey invalide.", 401);
    }
    valid.push(record);
  }

  return publishToPreKeyPool(
    getStandalonePreKeyStore(),
    poolKey(identity.canonicalAddress, input.deviceId),
    valid,
  );
}

export async function claimStandalonePreKey(input: {
  senderLocator: string;
  senderAuthToken: string | null;
  senderDeviceId: string;
  recipientCanonicalAddress: string;
  recipientDeviceId: string;
}) {
  authenticate(input.senderLocator, input.senderAuthToken, input.senderDeviceId);
  const recipient = resolveIdentity(input.recipientCanonicalAddress);
  const device = activeManifestDevice(recipient.canonicalAddress, input.recipientDeviceId);
  const key = poolKey(recipient.canonicalAddress, input.recipientDeviceId);

  while (true) {
    const record = claimFromPreKeyPool(getStandalonePreKeyStore(), key);
    if (!record) return null;
    if (
      record.canonicalAddress !== recipient.canonicalAddress ||
      record.deviceId !== input.recipientDeviceId ||
      isPreKeyExpired(record)
    ) continue;
    if (!(await verifyPreKeySignature(record, device.deviceSigningPublicKey))) continue;
    return record;
  }
}

export function standalonePreKeyStatus(input: {
  locator: string;
  authToken: string | null;
  deviceId: string;
}) {
  const identity = authenticate(input.locator, input.authToken, input.deviceId);
  activeManifestDevice(identity.canonicalAddress, input.deviceId);
  return {
    available: countPreKeyPool(
      getStandalonePreKeyStore(),
      poolKey(identity.canonicalAddress, input.deviceId),
    ),
  };
}
