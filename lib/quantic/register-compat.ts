import { createHash } from "node:crypto";

import { assertDeviceIdMatchesDigest } from "./device-id-core.mjs";
import { exportRelayState, restoreRelayState, type RelayPersistentState } from "./relay-state.ts";
import { registerIdentity, RelayError, type QuanticPublicKey } from "./relay.ts";

type RegisterInput = Parameters<typeof registerIdentity>[0];
type RelayQueue = RelayPersistentState["queues"][number][1];
type RelayReceipts = RelayPersistentState["receipts"][number][1];

function samePublicPoint(left: QuanticPublicKey, right: QuanticPublicKey) {
  return (
    left?.kty === "EC" &&
    right?.kty === "EC" &&
    left.crv === "P-256" &&
    right.crv === "P-256" &&
    left.x === right.x &&
    left.y === right.y
  );
}

function deviceDigest(key: QuanticPublicKey) {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new RelayError("Clé publique de chiffrement invalide.", 400);
  }
  return createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex");
}

function dedupeById<T extends { id: string }>(items: T[], max = 500) {
  const byId = new Map<string, T>();
  for (const item of items) byId.set(item.id, item);
  return [...byId.values()].slice(-max);
}

function migrateQueues(
  entries: RelayPersistentState["queues"],
  canonicalAddress: string,
  oldDeviceId: string,
  newDeviceId: string,
) {
  const oldMailbox = `${canonicalAddress}#${oldDeviceId}`;
  const newMailbox = `${canonicalAddress}#${newDeviceId}`;
  const merged = new Map<string, RelayQueue>();

  for (const [key, items] of entries) {
    const targetKey = key === oldMailbox ? newMailbox : key;
    const migrated = items.map((item) => ({
      ...item,
      ...(item.from === canonicalAddress && item.fromDeviceId === oldDeviceId
        ? { fromDeviceId: newDeviceId }
        : {}),
      ...(item.to === canonicalAddress && item.toDeviceId === oldDeviceId
        ? { toDeviceId: newDeviceId }
        : {}),
    }));
    merged.set(targetKey, dedupeById([...(merged.get(targetKey) ?? []), ...migrated]));
  }
  return [...merged.entries()] as RelayPersistentState["queues"];
}

function migrateReceipts(
  entries: RelayPersistentState["receipts"],
  canonicalAddress: string,
  oldDeviceId: string,
  newDeviceId: string,
) {
  const oldMailbox = `${canonicalAddress}#${oldDeviceId}`;
  const newMailbox = `${canonicalAddress}#${newDeviceId}`;
  const merged = new Map<string, RelayReceipts>();

  for (const [key, items] of entries) {
    const targetKey = key === oldMailbox ? newMailbox : key;
    const migrated = items.map((item) => ({
      ...item,
      ...(item.from === canonicalAddress && item.fromDeviceId === oldDeviceId
        ? { fromDeviceId: newDeviceId }
        : {}),
      ...(item.to === canonicalAddress && item.toDeviceId === oldDeviceId
        ? { toDeviceId: newDeviceId }
        : {}),
    }));
    merged.set(targetKey, dedupeById([...(merged.get(targetKey) ?? []), ...migrated]));
  }
  return [...merged.entries()] as RelayPersistentState["receipts"];
}

function migrateRootSnapshot(
  snapshot: RelayPersistentState,
  canonicalAddress: string,
  publicKey: QuanticPublicKey,
  oldDeviceId: string,
  newDeviceId: string,
) {
  try {
    assertDeviceIdMatchesDigest(newDeviceId, deviceDigest(publicKey));
  } catch (error) {
    throw new RelayError(
      error instanceof Error ? error.message : "Identifiant cryptographique de l’appareil invalide.",
      400,
    );
  }

  const oldKey = `${canonicalAddress}#${oldDeviceId}`;
  const newKey = `${canonicalAddress}#${newDeviceId}`;
  const oldEntry = snapshot.devices.find(([key, device]) =>
    key === oldKey &&
    device.kind === "root" &&
    samePublicPoint(device.publicKey, publicKey),
  );
  if (!oldEntry) {
    throw new RelayError("Migration de l’appareil racine impossible : clé serveur incohérente.", 409);
  }

  const conflicting = snapshot.devices.find(([key, device]) =>
    key === newKey && !samePublicPoint(device.publicKey, publicKey),
  );
  if (conflicting) {
    throw new RelayError("Migration de l’appareil racine impossible : identifiant déjà utilisé.", 409);
  }

  const [, root] = oldEntry;
  snapshot.devices = snapshot.devices
    .filter(([key]) => key !== oldKey && key !== newKey)
    .concat([[newKey, { ...root, deviceId: newDeviceId, updatedAt: new Date().toISOString() }]]);
  snapshot.queues = migrateQueues(snapshot.queues, canonicalAddress, oldDeviceId, newDeviceId);
  snapshot.receipts = migrateReceipts(snapshot.receipts, canonicalAddress, oldDeviceId, newDeviceId);

  // Prekeys are signed over their deviceId. They cannot be rewritten safely; the
  // client replenishes a fresh pool immediately after registration.
  snapshot.preKeyPools = snapshot.preKeyPools.filter(([key]) => key !== oldKey && key !== newKey);
  snapshot.consumedPreKeys = snapshot.consumedPreKeys.filter(
    ([key]) => !key.startsWith(`${oldKey}#`) && !key.startsWith(`${newKey}#`),
  );
  snapshot.savedAt = new Date().toISOString();
}

/**
 * Register a root identity while treating 10-hex and 32-hex device IDs that
 * derive from the exact same P-256 public key as migration aliases, not as two
 * different physical devices.
 */
export function registerIdentityCompat(input: RegisterInput) {
  const first = registerIdentity(input);
  if (!input.deviceId || first.rootDeviceId === input.deviceId) return first;

  const snapshot = exportRelayState();
  migrateRootSnapshot(
    snapshot,
    first.canonicalAddress,
    input.publicKey,
    first.rootDeviceId,
    input.deviceId,
  );
  restoreRelayState(snapshot);

  const migrated = registerIdentity(input);
  if (migrated.rootDeviceId !== input.deviceId) {
    throw new RelayError("La migration de l’appareil racine n’a pas été appliquée.", 409);
  }
  return migrated;
}
