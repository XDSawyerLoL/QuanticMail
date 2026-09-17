import type {
  QuanticFederationReceipt,
  QuanticFederationReceiptPayload,
  QuanticPortableEnvelope,
  QuanticRouteManifest,
  QuanticRouteManifestPayload,
} from "./federation-types.ts";

export function canonicalPortableEnvelopeText(envelope: QuanticPortableEnvelope): string;
export function canonicalRouteManifestText(payload: QuanticRouteManifestPayload): string;
export function canonicalFederationReceiptText(payload: QuanticFederationReceiptPayload): string;
export function envelopeDigest(envelope: QuanticPortableEnvelope): Promise<string>;
export function validatePortableEnvelopeShape(envelope: unknown): QuanticPortableEnvelope;
export function validateRouteManifestShape(manifest: unknown): QuanticRouteManifest;
export function validateFederationReceiptShape(receipt: unknown): QuanticFederationReceipt;
