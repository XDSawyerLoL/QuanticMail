import { activeDevices } from "@/lib/quantic/manifest-core.mjs";
import { getManifest } from "@/lib/quantic/manifest-state";
import {
  createPreKeyPoolStore,
  publishToPreKeyPool,
  claimFromPreKeyPool,
  countPreKeyPool,
  type PreKeyPoolStore,
} from "@/lib/quantic/prekey-pool.mjs";
import {
  isPreKeyExpired,
  validatePreKeyRecord,
  verifyPreKeySignature,
  type SignedPreKeyRecord,
} from "@/lib/quantic/prekey-core.mjs";
import { pullEnvelopes, resolveIdentity, RelayError } from "@/lib/quantic/relay";

declare global {
  var __quanticPreKeyPoolStore: PreKeyPoolStore | undefined;
}

const store = globalThis.__quanticPreKeyPoolStore ?? createPreKeyPoolStore();
globalThis.__quanticPreKeyPoolStore = store;

export class PreKeyRelayError extends Error {
  constructor(message: string, public readonly status = 400) {
    super(message);
  }
}

function poolKey(canonicalAddress: string, deviceId: string) {
  return `${canonicalAddress}#${deviceId}`;
}

function mapRelayError(error: unknown): never {
  if (error instanceof RelayError) throw new PreKeyRelayError(error.message, error.status);
  throw error;
}

function authenticate(locator: string, authToken: string | null, deviceId: string) {
  try {
    pullEnvelopes(locator, authToken, deviceId);
    return resolveIdentity(locator);
  } catch (error) {
    mapRelayError(error);
  }
}

async function activeManifestDevice(canonicalAddress: string, deviceId: string) {
  const manifest = await getManifest(canonicalAddress);
  if (!manifest) {
    throw new PreKeyRelayError("Les one-time prekeys nécessitent un manifeste V1 actif.", 409);
  }
  const device = activeDevices(manifest).find((item) => item.deviceId === deviceId);
  if (!device) {
    throw new PreKeyRelayError("Cet appareil n’est plus autorisé par le manifeste Quantic.", 401);
  }
  return device;
}

export async function publishPreKeys(input: {
  locator: string;
  authToken: string | null;
  deviceId: string;
  records: SignedPreKeyRecord[];
}) {
  const identity = authenticate(input.locator, input.authToken, input.deviceId);
  const device = await activeManifestDevice(identity.canonicalAddress, input.deviceId);
  if (!Array.isArray(input.records) || input.records.length > 64) {
    throw new PreKeyRelayError("Lot de prekeys invalide ou trop volumineux.", 400);
  }

  const valid: SignedPreKeyRecord[] = [];
  for (const record of input.records) {
    try {
      validatePreKeyRecord(record);
    } catch (error) {
      throw new PreKeyRelayError(error instanceof Error ? error.message : "Prekey invalide.", 400);
    }
    if (
      record.canonicalAddress !== identity.canonicalAddress ||
      record.deviceId !== input.deviceId
    ) {
      throw new PreKeyRelayError("La prekey ne correspond pas à l’appareil authentifié.", 400);
    }
    if (isPreKeyExpired(record)) continue;
    if (!(await verifyPreKeySignature(record, device.deviceSigningPublicKey))) {
      throw new PreKeyRelayError("Signature de prekey invalide.", 401);
    }
    valid.push(record);
  }

  return publishToPreKeyPool(
    store,
    poolKey(identity.canonicalAddress, input.deviceId),
    valid,
  );
}

export async function claimPreKey(input: {
  senderLocator: string;
  senderAuthToken: string | null;
  senderDeviceId: string;
  recipientCanonicalAddress: string;
  recipientDeviceId: string;
}) {
  authenticate(input.senderLocator, input.senderAuthToken, input.senderDeviceId);
  const recipient = resolveIdentity(input.recipientCanonicalAddress);
  const device = await activeManifestDevice(recipient.canonicalAddress, input.recipientDeviceId);
  const key = poolKey(recipient.canonicalAddress, input.recipientDeviceId);

  while (true) {
    const record = claimFromPreKeyPool(store, key);
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

export async function preKeyStatus(input: {
  locator: string;
  authToken: string | null;
  deviceId: string;
}) {
  const identity = authenticate(input.locator, input.authToken, input.deviceId);
  await activeManifestDevice(identity.canonicalAddress, input.deviceId);
  return {
    available: countPreKeyPool(store, poolKey(identity.canonicalAddress, input.deviceId)),
  };
}
