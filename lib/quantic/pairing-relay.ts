import { activeDevices } from "@/lib/quantic/manifest-core.mjs";
import { getManifest } from "@/lib/quantic/manifest-state";
import {
  attachPairingPackage,
  createInvite,
  createPairingStore,
  getPairingRequest,
  pairingStatus,
  submitPairingRequest,
  takePairingPackage,
  type PairingStore,
} from "@/lib/quantic/pairing-store.mjs";
import type { PublicDeviceRequest } from "@/lib/quantic/device";
import { pullEnvelopes, RelayError, resolveIdentity } from "@/lib/quantic/relay";

declare global {
  var __quanticPairingStore: PairingStore | undefined;
}

const store = globalThis.__quanticPairingStore ?? createPairingStore();
globalThis.__quanticPairingStore = store;

export class PairingRelayError extends Error {
  constructor(message: string, public readonly status = 400) {
    super(message);
  }
}

function mapError(error: unknown): never {
  if (error instanceof PairingRelayError) throw error;
  if (error instanceof RelayError) throw new PairingRelayError(error.message, error.status);
  const message = error instanceof Error ? error.message : "Pairing Quantic invalide.";
  const status = /expir/i.test(message) ? 410 : /secret/i.test(message) ? 401 : /introuvable|consomm/i.test(message) ? 404 : 400;
  throw new PairingRelayError(message, status);
}

async function authenticateRoot(locator: string, authToken: string | null, deviceId: string) {
  try {
    pullEnvelopes(locator, authToken, deviceId);
    const identity = resolveIdentity(locator);
    const manifest = await getManifest(identity.canonicalAddress);
    if (!manifest) throw new PairingRelayError("Un manifeste V1 est requis pour le pairing QR.", 409);
    const root = activeDevices(manifest).find((item) => item.kind === "root");
    if (!root || root.deviceId !== deviceId) {
      throw new PairingRelayError("Seul l’appareil maître peut autoriser un pairing QR.", 403);
    }
    return { identity, root };
  } catch (error) {
    mapError(error);
  }
}

export async function createPairingInvite(input: {
  locator: string;
  authToken: string | null;
  rootDeviceId: string;
  secret: string;
}) {
  const { identity, root } = await authenticateRoot(input.locator, input.authToken, input.rootDeviceId);
  return createInvite(
    store,
    { canonicalAddress: identity.canonicalAddress, rootDeviceId: root.deviceId },
    input.secret,
  );
}

function validateRequest(value: unknown): asserts value is PublicDeviceRequest {
  const request = value as Partial<PublicDeviceRequest> | null;
  if (
    !request ||
    request.format !== "quantic-device-request" ||
    request.version !== 1 ||
    typeof request.canonicalAddress !== "string" ||
    typeof request.deviceId !== "string" ||
    typeof request.deviceLabel !== "string" ||
    !request.devicePublicKey ||
    !request.deviceSigningPublicKey
  ) {
    throw new PairingRelayError("Demande d’appareil invalide.", 400);
  }
}

export function submitPairingDeviceRequest(input: {
  inviteId: string;
  secret: string;
  request: unknown;
}) {
  try {
    validateRequest(input.request);
    const status = pairingStatus(store, input.inviteId, input.secret);
    if (input.request.canonicalAddress !== status.canonicalAddress) {
      throw new PairingRelayError("La demande vise une autre identité Quantic.", 400);
    }
    return submitPairingRequest(store, input.inviteId, input.secret, input.request);
  } catch (error) {
    mapError(error);
  }
}

export function readPairingStatus(inviteId: string, secret: string) {
  try {
    return pairingStatus(store, inviteId, secret);
  } catch (error) {
    mapError(error);
  }
}

export function readPairingDeviceRequest(inviteId: string, secret: string) {
  try {
    return getPairingRequest(store, inviteId, secret) as PublicDeviceRequest | null;
  } catch (error) {
    mapError(error);
  }
}

export async function storePairingPackage(input: {
  locator: string;
  authToken: string | null;
  rootDeviceId: string;
  inviteId: string;
  secret: string;
  encryptedPackage: unknown;
}) {
  const { identity } = await authenticateRoot(input.locator, input.authToken, input.rootDeviceId);
  try {
    const status = pairingStatus(store, input.inviteId, input.secret);
    if (status.canonicalAddress !== identity.canonicalAddress || status.rootDeviceId !== input.rootDeviceId) {
      throw new PairingRelayError("Cette invitation appartient à un autre appareil maître.", 403);
    }
    return attachPairingPackage(store, input.inviteId, input.secret, input.encryptedPackage);
  } catch (error) {
    mapError(error);
  }
}

export function takeEncryptedPairingPackage(inviteId: string, secret: string) {
  try {
    return takePairingPackage(store, inviteId, secret);
  } catch (error) {
    mapError(error);
  }
}
