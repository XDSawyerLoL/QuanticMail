import { activeDevices, mergeManifestState } from "@/lib/quantic/manifest-core.mjs";
import { assertVerifiedManifest } from "@/lib/quantic/manifest-node.mjs";
import { loadRegistryManifest, saveRegistryManifest } from "@/lib/quantic/registry-store";
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

export function acceptManifestInMemory(manifest: QuanticIdentityManifest) {
  try {
    assertVerifiedManifest(manifest);
  } catch (error) {
    throw new ManifestStateError(error instanceof Error ? error.message : "Manifeste Quantic invalide.", 401);
  }
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
  const accepted = acceptManifestInMemory(manifest);
  try {
    const checkpoint = await saveRegistryManifest(accepted);
    return { manifest: accepted, checkpoint };
  } catch (error) {
    return {
      manifest: accepted,
      checkpoint: {
        persisted: false,
        mode: "github" as const,
        error: error instanceof Error ? error.message : "Checkpoint durable indisponible.",
      },
    };
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
