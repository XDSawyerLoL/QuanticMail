import { createHash } from "node:crypto";

const CANONICAL_ADDRESS = /^[a-z0-9][a-z0-9._-]{2,31}~[0-9a-f]{10}@quantic$/;

export function normalizeCanonicalAddress(value) {
  const canonical = String(value ?? "").trim().toLowerCase();
  if (!CANONICAL_ADDRESS.test(canonical)) {
    throw new Error("Adresse Quantic canonique invalide.");
  }
  return canonical;
}

export function registryFilePath(canonicalAddress) {
  const canonical = normalizeCanonicalAddress(canonicalAddress);
  const digest = createHash("sha256").update(canonical, "utf8").digest("hex");
  return `registry/identities/${digest}.json`;
}
