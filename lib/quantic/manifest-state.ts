import { activeDevices, mergeManifestState } from "@/lib/quantic/manifest-core.mjs";
import { reconcileManifestAuthority } from "@/lib/quantic/manifest-authority-core.mjs";
import { assertVerifiedManifest } from "@/lib/quantic/manifest-node.mjs";
import {
  loadRegistryManifest,
  registryStatus,
  saveRegistryManifest,
} from "@/lib/quantic/registry-store";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";

declare global {
  var __quanticManifestState: Map<string, QuanticIdentityManifest> | undefined;
}

const manifests = globalThis.__quanticManifestState ?? new Map<string, QuanticIdentityManifest>();
globalThis.__quanticManifestState = manifests;

export class ManifestStateError extends Error {
  constructor(message: string, public readonly status = 400) {
    super(message);
  }
}

export function getCachedManifest(canonicalAddress: string) {
  return manifests.get(canonicalAddress.trim().toLowerCase()) ?? null;
}

function assertVerified(manifest: QuanticIdentityManifest, message = "Manifeste Quantic invalide.") {
  try {
    assertVerifiedManifest(manifest);
  } catch (error) {
    throw new ManifestStateError(error instanceof Error ? error.message : message, 401);
  }
}

export function acceptManifestInMemory(manifest: QuanticIdentityManifest) {
  assertVerified(manifest);
  const canonical = manifest.payload.canonicalAddress;
  const current = manifests.get(canonical) ?? null;
  try {
    const accepted = mergeManifestState(current, manifest);
    manifests.set(canonical, accepted);
    return accepted;
  } catch (error) {
    throw new ManifestStateError(error instanceof Error ? error.message : "Conflit de manifeste Quantic.", 409);
  }
}

export async function publishManifest(manifest: QuanticIdentityManifest) {
  assertVerified(manifest);
  const canonical = manifest.payload.canonicalAddress;
  const current = manifests.get(canonical) ?? null;
  const status = registryStatus();
  let durable: QuanticIdentityManifest | null = null;

  if (status.configured) {
    try {
      durable = await loadRegistryManifest(canonical);
      if (durable) assertVerified(durable, "Checkpoint Quantic durable invalide.");
    } catch (error) {
      if (error instanceof ManifestStateError) throw error;
      throw new ManifestStateError(
        error instanceof Error ? `Registre durable indisponible : ${error.message}` : "Registre durable indisponible.",
        503,
      );
    }
  }

  let accepted: QuanticIdentityManifest;
  try {
    accepted = reconcileManifestAuthority(current, durable, manifest);
  } catch (error) {
    throw new ManifestStateError(error instanceof Error ? error.message : "Conflit de manifeste Quantic.", 409);
  }

  if (!status.configured) {
    manifests.set(canonical, accepted);
    return {
      manifest: accepted,
      checkpoint: { persisted: false, mode: "memory" as const },
    };
  }

  try {
    const checkpoint = await saveRegistryManifest(accepted);
    manifests.set(canonical, accepted);
    return { manifest: accepted, checkpoint };
  } catch (error) {
    throw new ManifestStateError(
      error instanceof Error ? `Checkpoint durable refusé : ${error.message}` : "Checkpoint durable refusé.",
      503,
    );
  }
}

export async function getManifest(canonicalAddress: string) {
  const canonical = canonicalAddress.trim().toLowerCase();
  const cached = manifests.get(canonical);
  if (cached) return cached;
  try {
    const remote = await loadRegistryManifest(canonical);
    if (!remote) return null;
    return acceptManifestInMemory(remote);
  } catch {
    return null;
  }
}

export function activeManifestDevices(canonicalAddress: string) {
  const manifest = getCachedManifest(canonicalAddress);
  return manifest ? activeDevices(manifest) : null;
}

export function assertManifestDeviceActive(canonicalAddress: string, deviceId: string) {
  const manifest = getCachedManifest(canonicalAddress);
  if (!manifest) return;
  const active = activeDevices(manifest).some((device) => device.deviceId === deviceId);
  if (!active) {
    throw new ManifestStateError("Cet appareil a été révoqué ou n’est pas autorisé par le manifeste Quantic courant.", 401);
  }
}
