import { createHash } from "node:crypto";

const HANDLE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const CANONICAL_ADDRESS = /^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/;

export function normalizeCanonicalAddress(value) {
  const canonical = String(value ?? "").trim().toLowerCase();
  if (!CANONICAL_ADDRESS.test(canonical)) {
    throw new Error("Adresse Quantic canonique invalide.");
  }
  return canonical;
}

export function normalizeRegistryHandle(value) {
  const locator = String(value ?? "").trim().toLowerCase();
  const handle = locator.endsWith("@quantic") ? locator.slice(0, -"@quantic".length) : locator;
  if (!HANDLE.test(handle) || handle.includes("~")) {
    throw new Error("Handle Quantic court invalide.");
  }
  return handle;
}

export function filterRegistryManifestsByHandle(locator, manifests) {
  const handle = normalizeRegistryHandle(locator);
  if (!Array.isArray(manifests)) return [];
  return manifests.filter((manifest) => {
    const payload = manifest?.payload;
    if (!payload || typeof payload.handle !== "string" || typeof payload.canonicalAddress !== "string") return false;
    if (payload.handle.trim().toLowerCase() !== handle) return false;
    try {
      const canonical = normalizeCanonicalAddress(payload.canonicalAddress);
      return canonical.startsWith(`${handle}~`);
    } catch {
      return false;
    }
  });
}

export function registryFilePath(canonicalAddress) {
  const canonical = normalizeCanonicalAddress(canonicalAddress);
  const digest = createHash("sha256").update(canonical, "utf8").digest("hex");
  return `registry/identities/${digest}.json`;
}
