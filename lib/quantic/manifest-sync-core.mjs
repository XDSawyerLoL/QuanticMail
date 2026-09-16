import { mergeManifestState, validateManifestShape } from "./manifest-core.mjs";

export function decideManifestSync(localManifest, remoteManifest) {
  if (!localManifest && !remoteManifest) {
    return { action: "none", manifest: null };
  }
  if (!localManifest) {
    validateManifestShape(remoteManifest);
    return { action: "adopt-remote", manifest: remoteManifest };
  }
  if (!remoteManifest) {
    validateManifestShape(localManifest);
    return { action: "publish-local", manifest: localManifest };
  }

  const localSequence = validateManifestShape(localManifest).sequence;
  const remoteSequence = validateManifestShape(remoteManifest).sequence;

  if (remoteSequence > localSequence) {
    const accepted = mergeManifestState(localManifest, remoteManifest);
    return { action: "adopt-remote", manifest: accepted };
  }
  if (localSequence > remoteSequence) {
    const accepted = mergeManifestState(remoteManifest, localManifest);
    return { action: "publish-local", manifest: accepted };
  }

  const accepted = mergeManifestState(localManifest, remoteManifest);
  return { action: "none", manifest: accepted };
}
