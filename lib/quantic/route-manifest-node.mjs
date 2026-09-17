import {
  createHash,
  createPublicKey,
  verify,
} from "node:crypto";

import {
  canonicalRouteManifestText,
  validateRouteManifestShape,
} from "./federation-core.mjs";
import { assertVerifiedManifest } from "./manifest-node.mjs";

function publicPoint(key) {
  return `P-256:${key.kty}:${key.crv}:${key.x}:${key.y}`;
}

export function relayIdForRouteKey(key) {
  const publicKey = createPublicKey({ key, format: "jwk" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spki).digest("hex");
}

export function verifyRouteManifestSignature(manifest) {
  try {
    const validated = validateRouteManifestShape(manifest);
    const payload = validated.payload;
    return verify(
      "sha256",
      Buffer.from(canonicalRouteManifestText(payload), "utf8"),
      {
        key: createPublicKey({ key: payload.identitySigningPublicKey, format: "jwk" }),
        dsaEncoding: "ieee-p1363",
      },
      Buffer.from(validated.signatures.p256, "base64"),
    );
  } catch {
    return false;
  }
}

export function assertVerifiedRouteManifest(manifest, identityManifest, nowMs = Date.now()) {
  const route = validateRouteManifestShape(manifest);
  const identity = assertVerifiedManifest(identityManifest);
  const payload = route.payload;
  const identityPayload = identity.payload;

  if (payload.canonicalAddress !== identityPayload.canonicalAddress) {
    throw new Error("Le Route Manifest vise une autre identité Quantic.");
  }
  if (publicPoint(payload.identitySigningPublicKey) !== publicPoint(identityPayload.identitySigningPublicKey)) {
    throw new Error("La clé de propriété du Route Manifest ne correspond pas à l’identité.");
  }
  if (payload.identityManifestSequence > identityPayload.sequence) {
    throw new Error("Le Route Manifest référence une séquence d’identité indisponible.");
  }
  if (Date.parse(payload.expiresAt) <= nowMs) {
    throw new Error("Route Manifest expiré.");
  }

  for (const relay of payload.relays) {
    const expectedRelayId = relayIdForRouteKey(relay.classicalSigningPublicKey);
    if (relay.relayId !== expectedRelayId) {
      throw new Error("Relay ID incohérent avec la clé publique du relais.");
    }
    if (Date.parse(relay.expiresAt) <= nowMs) {
      throw new Error("Entrée de relais expirée.");
    }
  }

  if (!verifyRouteManifestSignature(route)) {
    throw new Error("Signature du Route Manifest Quantic invalide.");
  }
  return route;
}

export function mergeRouteManifestState(current, incoming) {
  const next = validateRouteManifestShape(incoming);
  if (!current) return next;
  const previous = validateRouteManifestShape(current);

  if (previous.payload.canonicalAddress !== next.payload.canonicalAddress) {
    throw new Error("Conflit d’identité dans le Route Manifest.");
  }
  if (publicPoint(previous.payload.identitySigningPublicKey) !== publicPoint(next.payload.identitySigningPublicKey)) {
    throw new Error("Conflit de clé de propriété dans le Route Manifest.");
  }
  if (next.payload.sequence < previous.payload.sequence) {
    throw new Error("Route Manifest rollback refusé : séquence plus ancienne.");
  }
  if (next.payload.sequence === previous.payload.sequence) {
    if (canonicalRouteManifestText(previous.payload) !== canonicalRouteManifestText(next.payload)) {
      throw new Error("Conflit de Route Manifest pour la même séquence.");
    }
    return previous;
  }
  return next;
}
