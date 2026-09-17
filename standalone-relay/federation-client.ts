import { createHash, randomBytes } from "node:crypto";

import {
  canonicalPortableEnvelopeText,
  validateRouteManifestShape,
} from "../lib/quantic/federation-core.mjs";
import type {
  QuanticFederationReceipt,
  QuanticPortableEnvelope,
  QuanticRouteManifest,
} from "../lib/quantic/federation-types.ts";
import type { QuanticIdentityManifest } from "../lib/quantic/manifest-types.ts";
import { assertVerifiedRouteManifest } from "../lib/quantic/route-manifest-node.mjs";
import {
  signRelayHello,
  verifyRelayHello,
  type RelayIdentity,
  type SignedRelayHello,
} from "./identity.ts";

export type FederationForwardInput = {
  federationId: string;
  envelope: QuanticPortableEnvelope;
  senderIdentityManifest: QuanticIdentityManifest;
  recipientIdentityManifest: QuanticIdentityManifest;
  recipientRouteManifest: QuanticRouteManifest;
  senderCryptoProfile?: unknown;
};

export type FederationClientOptions = {
  identity: RelayIdentity;
  publicEndpoint: string;
  fetchImpl?: typeof fetch;
};

function normalizeOrigin(value: string) {
  const url = new URL(value);
  return url.origin;
}

function sameP256Key(first: JsonWebKey, second: JsonWebKey) {
  return (
    first?.kty === "EC" &&
    second?.kty === "EC" &&
    first.crv === "P-256" &&
    second.crv === "P-256" &&
    first.x === second.x &&
    first.y === second.y
  );
}

export function portableEnvelopeDigest(envelope: QuanticPortableEnvelope) {
  return createHash("sha256")
    .update(canonicalPortableEnvelopeText(envelope), "utf8")
    .digest("hex");
}

export function federationForwardNonce(federationId: string) {
  return `forward-${createHash("sha256").update(federationId, "utf8").digest("hex").slice(0, 32)}`;
}

async function pinDestinationRelay(
  routeRelay: QuanticRouteManifest["payload"]["relays"][number],
  fetchImpl: typeof fetch,
) {
  const nonce = randomBytes(18).toString("base64url");
  const response = await fetchImpl(`${routeRelay.endpoint}/api/quantic/federation/hello`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce }),
  });
  if (!response.ok) {
    throw new Error(`Handshake du relais ${routeRelay.relayId} refusé (${response.status}).`);
  }
  const hello = verifyRelayHello(await response.json(), nonce, routeRelay.relayId);
  if (!sameP256Key(hello.classicalSigningPublicKey, routeRelay.classicalSigningPublicKey)) {
    throw new Error("La clé du relais distant ne correspond pas au Route Manifest.");
  }
  if (normalizeOrigin(hello.endpoint) !== normalizeOrigin(routeRelay.endpoint)) {
    throw new Error("L’endpoint annoncé par le relais distant ne correspond pas au Route Manifest.");
  }
  return hello;
}

export async function forwardToRoute(
  input: FederationForwardInput,
  options: FederationClientOptions,
) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const route = assertVerifiedRouteManifest(
    validateRouteManifestShape(input.recipientRouteManifest),
    input.recipientIdentityManifest,
  ) as QuanticRouteManifest;
  if (route.payload.canonicalAddress !== input.envelope.to) {
    throw new Error("Le Route Manifest ne correspond pas au destinataire de l’enveloppe.");
  }

  const envelopeDigest = portableEnvelopeDigest(input.envelope);
  const originRelay = signRelayHello(
    options.identity,
    options.publicEndpoint,
    federationForwardNonce(input.federationId),
  );
  const expiresAt = new Date(
    Math.min(Date.parse(input.envelope.expiresAt), Date.now() + 24 * 60 * 60 * 1000),
  ).toISOString();
  const candidates = [...route.payload.relays]
    .filter((relay) => relay.protocols.includes("quantic-federation/1") && Date.parse(relay.expiresAt) > Date.now())
    .sort((a, b) => a.priority - b.priority || a.relayId.localeCompare(b.relayId));
  if (candidates.length === 0) throw new Error("Aucun relais fédéré valide n’est annoncé par le destinataire.");

  const failures: string[] = [];
  for (const relay of candidates) {
    try {
      await pinDestinationRelay(relay, fetchImpl);
      const response = await fetchImpl(`${relay.endpoint}/api/quantic/federation/forward`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          format: "quantic-federation-forward",
          version: 1,
          federationId: input.federationId,
          originRelay,
          previousRelayId: options.identity.relayId,
          hopLimit: 4,
          visitedRelayIds: [options.identity.relayId],
          expiresAt,
          senderIdentityManifest: input.senderIdentityManifest,
          senderCryptoProfile: input.senderCryptoProfile ?? null,
          recipientIdentityManifest: input.recipientIdentityManifest,
          recipientRouteManifest: route,
          envelope: input.envelope,
          previousRelayAttestation: originRelay.p256Signature,
        }),
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(`Forward refusé (${response.status})${text ? `: ${text.slice(0, 300)}` : ""}`);
      }
      const result = await response.json() as { id?: string; queuedAt?: string; duplicate?: boolean };
      return {
        relayId: relay.relayId,
        endpoint: relay.endpoint,
        routeSequence: route.payload.sequence,
        envelopeDigest,
        result,
      };
    } catch (error) {
      failures.push(`${relay.relayId.slice(0, 12)}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  throw new Error(`Aucun relais destinataire joignable. ${failures.join(" | ")}`);
}

export async function postFederationReceipt(
  receipt: QuanticFederationReceipt,
  originEndpoint: string,
  fetchImpl: typeof fetch = fetch,
) {
  const response = await fetchImpl(`${normalizeOrigin(originEndpoint)}/api/quantic/federation/receipt`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ receipt }),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Reçu de fédération refusé (${response.status})${text ? `: ${text.slice(0, 300)}` : ""}`);
  }
  return response.json() as Promise<{ accepted: boolean; duplicate?: boolean }>;
}
