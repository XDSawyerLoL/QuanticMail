import { mergeManifestState, validateManifestShape } from "./manifest-core.mjs";

function newestCompatible(first, second) {
  if (!first) return second ?? null;
  if (!second) return first;
  const firstSequence = validateManifestShape(first).sequence;
  const secondSequence = validateManifestShape(second).sequence;
  if (secondSequence >= firstSequence) return mergeManifestState(first, second);
  return mergeManifestState(second, first);
}

export function reconcileManifestAuthority(cachedManifest, durableManifest, incomingManifest) {
  const baseline = newestCompatible(cachedManifest, durableManifest);
  return mergeManifestState(baseline, incomingManifest);
}
