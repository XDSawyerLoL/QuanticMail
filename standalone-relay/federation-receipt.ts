import {
  createPublicKey,
  sign,
  verify,
} from "node:crypto";

import {
  canonicalFederationReceiptText,
  validateFederationReceiptShape,
  validateRouteManifestShape,
} from "../lib/quantic/federation-core.mjs";
import type {
  QuanticFederationReceipt,
  QuanticFederationReceiptPayload,
  QuanticRouteManifest,
} from "../lib/quantic/federation-types.ts";
import {
  relayIdForPublicKey,
  type RelayIdentity,
} from "./identity.ts";

export function signFederationReceipt(
  identity: RelayIdentity,
  input: Omit<QuanticFederationReceiptPayload, "version" | "destinationRelayId">,
): QuanticFederationReceipt {
  const relayId = relayIdForPublicKey(identity.publicKeyJwk);
  if (relayId !== identity.relayId) throw new Error("Identité de relais incohérente.");
  const payload: QuanticFederationReceiptPayload = {
    version: 1,
    ...input,
    destinationRelayId: relayId,
  };
  const p256Signature = sign(
    "sha256",
    Buffer.from(canonicalFederationReceiptText(payload), "utf8"),
    { key: identity.privateKeyPem, dsaEncoding: "ieee-p1363" },
  ).toString("base64");
  return {
    format: "quantic-federation-receipt",
    version: 1,
    payload,
    p256Signature,
  };
}

export function verifyFederationReceipt(
  value: unknown,
  routeValue: QuanticRouteManifest,
  nowMs = Date.now(),
): QuanticFederationReceipt {
  const receipt = validateFederationReceiptShape(value) as QuanticFederationReceipt;
  const route = validateRouteManifestShape(routeValue) as QuanticRouteManifest;
  if (receipt.payload.to !== route.payload.canonicalAddress) {
    throw new Error("Le reçu ne correspond pas au Route Manifest destinataire.");
  }
  if (receipt.payload.routeSequence !== route.payload.sequence) {
    throw new Error("Séquence du Route Manifest du reçu incohérente.");
  }
  if (Date.parse(receipt.payload.expiresAt) <= nowMs) {
    throw new Error("Reçu de fédération expiré.");
  }
  if (Date.parse(receipt.payload.deliveredAt) > nowMs + 5 * 60 * 1000) {
    throw new Error("Date de livraison du reçu invalide.");
  }
  const relay = route.payload.relays.find(
    (entry) => entry.relayId === receipt.payload.destinationRelayId,
  );
  if (!relay) throw new Error("Le relais signataire du reçu n’est pas autorisé par la route.");
  if (relayIdForPublicKey(relay.classicalSigningPublicKey) !== relay.relayId) {
    throw new Error("Relay ID du reçu incohérent avec la clé de route.");
  }
  const valid = verify(
    "sha256",
    Buffer.from(canonicalFederationReceiptText(receipt.payload), "utf8"),
    {
      key: createPublicKey({ key: relay.classicalSigningPublicKey, format: "jwk" }),
      dsaEncoding: "ieee-p1363",
    },
    Buffer.from(receipt.p256Signature, "base64"),
  );
  if (!valid) throw new Error("Signature du reçu de fédération invalide.");
  return receipt;
}
