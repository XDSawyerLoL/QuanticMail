const CANONICAL_ADDRESS = /^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/;
const APP_ID = /^[a-z0-9][a-z0-9._-]{1,47}$/;
const SCOPE = /^[a-z0-9][a-z0-9:._-]{1,63}$/;
const NONCE = /^[A-Za-z0-9._~-]{16,128}$/;

function publicPoint(key, label) {
  if (!key || key.kty !== "EC" || key.crv !== "P-256" || typeof key.x !== "string" || typeof key.y !== "string") {
    throw new Error(`${label} doit être une clé publique P-256.`);
  }
  return { kty: "EC", crv: "P-256", x: key.x, y: key.y };
}

export function normalizeAppId(value) {
  const app = String(value ?? "").trim().toLowerCase();
  if (!APP_ID.test(app)) throw new Error("Identifiant d’application Quantic invalide.");
  return app;
}

export function normalizeAppScopes(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 32) {
    throw new Error("Scopes d’application Quantic invalides.");
  }
  const normalized = [...new Set(value.map((scope) => String(scope ?? "").trim().toLowerCase()))].sort();
  if (normalized.length !== value.length || normalized.some((scope) => !SCOPE.test(scope))) {
    throw new Error("Scopes d’application Quantic invalides.");
  }
  return normalized;
}

export function normalizeAppCapabilityPayload(payload) {
  if (!payload || typeof payload !== "object" || payload.version !== 1) {
    throw new Error("Payload de capacité Quantic invalide.");
  }
  const canonicalAddress = String(payload.canonicalAddress ?? "").trim().toLowerCase();
  if (!CANONICAL_ADDRESS.test(canonicalAddress)) throw new Error("Adresse canonique de capacité invalide.");
  const app = normalizeAppId(payload.app);
  const appSigningPublicKey = publicPoint(payload.appSigningPublicKey, "Clé d’application");
  const scopes = normalizeAppScopes(payload.scopes);
  if (!Number.isSafeInteger(payload.identityManifestSequence) || payload.identityManifestSequence < 1) {
    throw new Error("Séquence de manifeste de capacité invalide.");
  }
  const issuedAt = String(payload.issuedAt ?? "");
  const expiresAt = String(payload.expiresAt ?? "");
  const issuedMs = Date.parse(issuedAt);
  const expiresMs = Date.parse(expiresAt);
  if (!Number.isFinite(issuedMs) || !Number.isFinite(expiresMs) || expiresMs <= issuedMs) {
    throw new Error("Fenêtre temporelle de capacité invalide.");
  }
  const nonce = String(payload.nonce ?? "");
  if (!NONCE.test(nonce)) throw new Error("Nonce de capacité Quantic invalide.");
  return {
    version: 1,
    canonicalAddress,
    app,
    appSigningPublicKey,
    scopes,
    identityManifestSequence: payload.identityManifestSequence,
    issuedAt: new Date(issuedMs).toISOString(),
    expiresAt: new Date(expiresMs).toISOString(),
    nonce,
  };
}

export function canonicalAppCapabilityText(payload) {
  const normalized = normalizeAppCapabilityPayload(payload);
  return JSON.stringify({
    version: normalized.version,
    canonicalAddress: normalized.canonicalAddress,
    app: normalized.app,
    appSigningPublicKey: normalized.appSigningPublicKey,
    scopes: normalized.scopes,
    identityManifestSequence: normalized.identityManifestSequence,
    issuedAt: normalized.issuedAt,
    expiresAt: normalized.expiresAt,
    nonce: normalized.nonce,
  });
}
