import { createHash } from "node:crypto";

import {
  mergeManifestState,
} from "./manifest-core.mjs";
import { assertVerifiedManifest } from "./manifest-node.mjs";
import {
  assertVerifiedRouteManifest,
  mergeRouteManifestState,
} from "./route-manifest-node.mjs";

const CANONICAL_ADDRESS = /^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/;
const DISCOVERY_NAMESPACES = {
  identity: "quantic-identity:",
  crypto: "quantic-crypto:",
  route: "quantic-route:",
};
const DIGEST = /^[0-9a-f]{64}$/;

function normalizeCanonicalAddress(value) {
  const canonicalAddress = String(value ?? "").trim().toLowerCase();
  if (!CANONICAL_ADDRESS.test(canonicalAddress)) {
    throw new Error("Adresse Quantic canonique de découverte invalide.");
  }
  return canonicalAddress;
}

function publicPoint(key) {
  return `P-256:${key?.kty}:${key?.crv}:${key?.x}:${key?.y}`;
}

export function discoveryKey(kind, canonicalAddress) {
  const namespace = DISCOVERY_NAMESPACES[kind];
  if (!namespace) throw new Error("Type de clé Discovery Mesh invalide.");
  const canonical = normalizeCanonicalAddress(canonicalAddress);
  return createHash("sha256").update(`${namespace}${canonical}`).digest("hex");
}

function validatePinnedIdentity(current, incoming) {
  if (!current) return incoming;
  assertVerifiedManifest(current);
  return mergeManifestState(current, incoming);
}

function validatePinnedRoute(current, incoming) {
  if (!current) return incoming;
  return mergeRouteManifestState(current, incoming);
}

function validateOptionalCryptoProfile(profile, identityManifest, pinnedProfile, routeManifest, options) {
  const referencedSequence = routeManifest.payload.cryptoProfileSequence;
  const referencedDigest = routeManifest.payload.cryptoProfileDigest;
  const routeReferencesCrypto = referencedSequence !== null || referencedDigest !== null;

  if (!profile) {
    if (routeReferencesCrypto) {
      throw new Error("Le Route Manifest référence un Crypto Profile absent du bundle de découverte.");
    }
    return null;
  }

  if (typeof options.verifyCryptoProfile !== "function") {
    throw new Error("Un vérificateur Crypto Profile est requis pour ce bundle de découverte.");
  }

  const verified = options.verifyCryptoProfile(profile, identityManifest, pinnedProfile ?? null);
  const acceptedProfile = verified?.profile ?? verified;
  const digest = verified?.digest ?? null;
  if (!acceptedProfile?.payload) throw new Error("Crypto Profile de découverte invalide.");
  if (acceptedProfile.payload.canonicalAddress !== identityManifest.payload.canonicalAddress) {
    throw new Error("Le Crypto Profile vise une autre identité Quantic.");
  }
  if (
    publicPoint(acceptedProfile.payload.identitySigningPublicKey) !==
    publicPoint(identityManifest.payload.identitySigningPublicKey)
  ) {
    throw new Error("La clé de propriété du Crypto Profile ne correspond pas à l’identité.");
  }
  if (acceptedProfile.payload.identityManifestSequence > identityManifest.payload.sequence) {
    throw new Error("Le Crypto Profile référence une séquence d’identité indisponible.");
  }

  if (routeReferencesCrypto) {
    if (referencedSequence === null || referencedDigest === null) {
      throw new Error("Référence Crypto Profile incomplète dans le Route Manifest.");
    }
    if (acceptedProfile.payload.sequence !== referencedSequence) {
      throw new Error("Le Route Manifest ne référence pas la séquence Crypto Profile fournie.");
    }
    if (!digest || digest !== referencedDigest) {
      throw new Error("Le digest Crypto Profile ne correspond pas au Route Manifest.");
    }
  }

  return acceptedProfile;
}

export function validateDiscoveryBundle(bundle, pinnedState = {}, options = {}) {
  if (!bundle || typeof bundle !== "object") {
    throw new Error("Bundle Quantic Discovery invalide.");
  }
  const nowMs = Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
  const identityManifest = bundle.identityManifest;
  const routeManifest = bundle.routeManifest;
  if (!identityManifest || !routeManifest) {
    throw new Error("Le bundle Discovery doit contenir Identity Manifest et Route Manifest.");
  }

  assertVerifiedManifest(identityManifest);
  validatePinnedIdentity(pinnedState.identityManifest ?? null, identityManifest);
  assertVerifiedRouteManifest(routeManifest, identityManifest, nowMs);
  validatePinnedRoute(pinnedState.routeManifest ?? null, routeManifest);

  const canonicalAddress = normalizeCanonicalAddress(identityManifest.payload.canonicalAddress);
  if (routeManifest.payload.canonicalAddress !== canonicalAddress) {
    throw new Error("Les enregistrements Discovery ne visent pas la même identité.");
  }

  const cryptoProfile = validateOptionalCryptoProfile(
    bundle.cryptoProfile ?? null,
    identityManifest,
    pinnedState.cryptoProfile ?? null,
    routeManifest,
    options,
  );

  return {
    canonicalAddress,
    identityManifest,
    cryptoProfile,
    routeManifest,
  };
}

export function selectNewestValidRecord(records) {
  if (!Array.isArray(records) || records.length === 0) return null;

  let expectedKind = null;
  let expectedAddress = null;
  let highestSequence = -1;
  const bySequence = new Map();

  for (const record of records) {
    if (!record || typeof record !== "object") throw new Error("Enregistrement Discovery invalide.");
    if (!DISCOVERY_NAMESPACES[record.kind]) throw new Error("Type d’enregistrement Discovery invalide.");
    const canonicalAddress = normalizeCanonicalAddress(record.canonicalAddress);
    if (!Number.isSafeInteger(record.sequence) || record.sequence < 1) {
      throw new Error("Séquence d’enregistrement Discovery invalide.");
    }
    if (typeof record.digest !== "string" || !DIGEST.test(record.digest)) {
      throw new Error("Digest d’enregistrement Discovery invalide.");
    }

    expectedKind ??= record.kind;
    expectedAddress ??= canonicalAddress;
    if (record.kind !== expectedKind || canonicalAddress !== expectedAddress) {
      throw new Error("Les candidats Discovery ne désignent pas le même enregistrement.");
    }

    const priorDigest = bySequence.get(record.sequence);
    if (priorDigest && priorDigest !== record.digest) {
      if (record.sequence >= highestSequence) {
        throw new Error("Fork Discovery détecté pour une même séquence.");
      }
    } else {
      bySequence.set(record.sequence, record.digest);
    }
    highestSequence = Math.max(highestSequence, record.sequence);
  }

  const candidates = records.filter((record) => record.sequence === highestSequence);
  const digests = new Set(candidates.map((record) => record.digest));
  if (digests.size !== 1) throw new Error("Fork Discovery détecté pour la séquence la plus récente.");
  return candidates[0];
}
