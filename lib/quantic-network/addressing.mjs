const HANDLE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const CANONICAL = /^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/;

export function isCanonicalQuanticAddress(value) {
  return CANONICAL.test(String(value ?? "").trim().toLowerCase());
}

export function normalizeQuanticLocator(value) {
  const locator = String(value ?? "").trim().toLowerCase();
  if (CANONICAL.test(locator)) {
    return { kind: "canonical", value: locator, handle: locator.slice(0, locator.indexOf("~")) };
  }
  const handle = locator.endsWith("@quantic") ? locator.slice(0, -"@quantic".length) : locator;
  if (!HANDLE.test(handle) || handle.includes("~")) {
    throw new Error("Identité Quantic invalide.");
  }
  return { kind: "handle", value: `${handle}@quantic`, handle };
}
