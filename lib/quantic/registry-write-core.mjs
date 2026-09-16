import { canonicalManifestText, validateManifestShape } from "./manifest-core.mjs";

export function decideRegistryWrite(remoteManifest, nextManifest) {
  validateManifestShape(nextManifest);
  if (!remoteManifest) return "write";
  const remote = validateManifestShape(remoteManifest);
  const next = validateManifestShape(nextManifest);
  if (remote.canonicalAddress !== next.canonicalAddress) {
    throw new Error("Conflit d’identité canonique du registre.");
  }
  if (remote.sequence > next.sequence) {
    throw new Error("GitHub registry already contains a newer manifest sequence.");
  }
  if (remote.sequence === next.sequence) {
    if (canonicalManifestText(remote) !== canonicalManifestText(next)) {
      throw new Error("Conflit de manifeste dans le registre pour la même séquence.");
    }
    return "unchanged";
  }
  return "write";
}
