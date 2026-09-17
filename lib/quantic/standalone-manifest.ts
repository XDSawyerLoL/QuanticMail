import { mergeManifestState } from "./manifest-core.mjs";
import { assertVerifiedManifest } from "./manifest-node.mjs";
import type { QuanticIdentityManifest } from "./manifest-types";
import { RelayError } from "./relay.ts";
import { getStandaloneManifest, getStandaloneManifestStore } from "./standalone-v11-state.ts";

export function readStandaloneManifest(canonicalAddress: string) {
  return getStandaloneManifest(canonicalAddress);
}

export function publishStandaloneManifest(manifest: QuanticIdentityManifest) {
  try {
    assertVerifiedManifest(manifest);
  } catch (error) {
    throw new RelayError(
      error instanceof Error ? error.message : "Manifeste Quantic invalide.",
      401,
    );
  }

  const canonical = manifest.payload.canonicalAddress.trim().toLowerCase();
  const current = getStandaloneManifest(canonical);
  let accepted: QuanticIdentityManifest;
  try {
    accepted = mergeManifestState(current, manifest) as QuanticIdentityManifest;
  } catch (error) {
    throw new RelayError(
      error instanceof Error ? error.message : "Conflit de manifeste Quantic.",
      409,
    );
  }
  getStandaloneManifestStore().set(canonical, accepted);
  return accepted;
}
