import type { DeliveryReceipt, RelayEnvelope } from "../quantic/relay.ts";

export type QuanticDirectEnvelopeFrame = {
  format: "quantic-direct-frame";
  version: 1;
  type: "envelope";
  payload: RelayEnvelope;
};

export type QuanticDirectReceiptFrame = {
  format: "quantic-direct-frame";
  version: 1;
  type: "receipt";
  payload: DeliveryReceipt;
};

export type QuanticDirectFrame = QuanticDirectEnvelopeFrame | QuanticDirectReceiptFrame;

export function createDirectEnvelopeFrame(envelope: RelayEnvelope | Record<string, unknown>): QuanticDirectEnvelopeFrame;
export function createDirectReceiptFrame(receipt: DeliveryReceipt | Record<string, unknown>): QuanticDirectReceiptFrame;
export function parseDirectFrame(value: unknown): QuanticDirectFrame;
