import type {
  QuanticFederationReceipt,
  QuanticRouteManifest,
} from "../lib/quantic/federation-types.ts";

export type FederationSeenRecord = {
  federationId: string;
  envelopeDigest: string;
  expiresAt: string;
  result: "accepted" | "delivered";
};

export type FederationInboundRecord = {
  federationId: string;
  envelopeDigest: string;
  envelopeId: string;
  clientMessageId: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  originRelayId: string;
  originEndpoint: string;
  routeSequence: number;
  expiresAt: string;
};

export type FederationOutboundRecord = {
  federationId: string;
  envelopeDigest: string;
  clientMessageId: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  destinationRelayId: string;
  destinationEndpoint: string;
  routeSequence: number;
  routeManifest: QuanticRouteManifest;
  expiresAt: string;
  result: "pending" | "accepted" | "delivered";
};

export type PendingFederationReceipt = {
  federationId: string;
  receipt: QuanticFederationReceipt;
  originEndpoint: string;
  nextAttemptAt: string;
  attempts: number;
};

export type FederationStateEntries = {
  seen: Array<[string, FederationSeenRecord]>;
  inbound: Array<[string, FederationInboundRecord]>;
  outbound: Array<[string, FederationOutboundRecord]>;
  pendingReceipts: Array<[string, PendingFederationReceipt]>;
};

type FederationState = {
  seen: Map<string, FederationSeenRecord>;
  inbound: Map<string, FederationInboundRecord>;
  outbound: Map<string, FederationOutboundRecord>;
  pendingReceipts: Map<string, PendingFederationReceipt>;
};

declare global {
  var __quanticFederationState: FederationState | undefined;
}

const state: FederationState = globalThis.__quanticFederationState ?? {
  seen: new Map(),
  inbound: new Map(),
  outbound: new Map(),
  pendingReceipts: new Map(),
};
globalThis.__quanticFederationState = state;

const FEDERATION_ID = /^[A-Za-z0-9._:-]{12,128}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;

function jsonClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function validDate(value: string) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function assertSeenRecord(record: FederationSeenRecord) {
  if (!FEDERATION_ID.test(record.federationId)) throw new Error("Identifiant de fédération invalide.");
  if (!SHA256_HEX.test(record.envelopeDigest)) throw new Error("Digest de fédération invalide.");
  if (!validDate(record.expiresAt)) throw new Error("Expiration de fédération invalide.");
  if (record.result !== "accepted" && record.result !== "delivered") {
    throw new Error("État de fédération invalide.");
  }
}

function prune(nowMs: number) {
  for (const [key, record] of state.seen) {
    if (Date.parse(record.expiresAt) <= nowMs) state.seen.delete(key);
  }
  for (const [key, record] of state.inbound) {
    if (Date.parse(record.expiresAt) <= nowMs) state.inbound.delete(key);
  }
  for (const [key, record] of state.outbound) {
    if (Date.parse(record.expiresAt) <= nowMs) state.outbound.delete(key);
  }
  for (const [key, record] of state.pendingReceipts) {
    if (Date.parse(record.receipt.payload.expiresAt) <= nowMs) state.pendingReceipts.delete(key);
  }
}

export function checkFederationReplay(
  federationId: string,
  envelopeDigest: string,
  nowMs = Date.now(),
) {
  if (!FEDERATION_ID.test(federationId) || !SHA256_HEX.test(envelopeDigest)) {
    throw new Error("Identité de replay de fédération invalide.");
  }
  prune(nowMs);
  const existing = state.seen.get(federationId);
  if (!existing) return { duplicate: false as const };
  if (existing.envelopeDigest !== envelopeDigest) {
    throw new Error("Conflit de replay de fédération: même federationId avec un digest différent.");
  }
  return { duplicate: true as const };
}

export function recordFederationAccepted(record: Omit<FederationSeenRecord, "result"> & { result?: FederationSeenRecord["result"] }) {
  const normalized: FederationSeenRecord = {
    federationId: record.federationId,
    envelopeDigest: record.envelopeDigest,
    expiresAt: record.expiresAt,
    result: record.result ?? "accepted",
  };
  assertSeenRecord(normalized);
  const existing = state.seen.get(normalized.federationId);
  if (existing && existing.envelopeDigest !== normalized.envelopeDigest) {
    throw new Error("Conflit de replay de fédération.");
  }
  state.seen.set(normalized.federationId, jsonClone(normalized));
  return normalized;
}

export function markFederationDelivered(federationId: string) {
  const existing = state.seen.get(federationId);
  if (existing) state.seen.set(federationId, { ...existing, result: "delivered" });
}

export function rememberInboundFederation(record: FederationInboundRecord) {
  state.inbound.set(record.envelopeId, jsonClone(record));
}

export function inboundFederationForEnvelopeIds(ids: string[], nowMs = Date.now()) {
  prune(nowMs);
  const wanted = new Set(ids);
  return [...state.inbound.values()].filter((record) => wanted.has(record.envelopeId)).map(jsonClone);
}

export function removeInboundFederation(envelopeId: string) {
  state.inbound.delete(envelopeId);
}

export function rememberOutboundFederation(record: FederationOutboundRecord) {
  const existing = state.outbound.get(record.federationId);
  if (existing && existing.envelopeDigest !== record.envelopeDigest) {
    throw new Error("Conflit de sortie de fédération.");
  }
  state.outbound.set(record.federationId, jsonClone(record));
}

export function getOutboundFederation(federationId: string, nowMs = Date.now()) {
  prune(nowMs);
  const record = state.outbound.get(federationId);
  return record ? jsonClone(record) : null;
}

export function updateOutboundFederationResult(
  federationId: string,
  result: FederationOutboundRecord["result"],
) {
  const existing = state.outbound.get(federationId);
  if (!existing) return null;
  const next = { ...existing, result };
  state.outbound.set(federationId, next);
  return jsonClone(next);
}

export function queuePendingFederationReceipt(record: PendingFederationReceipt) {
  state.pendingReceipts.set(record.federationId, jsonClone(record));
}

export function pendingFederationReceipts(nowMs = Date.now()) {
  prune(nowMs);
  return [...state.pendingReceipts.values()].map(jsonClone);
}

export function removePendingFederationReceipt(federationId: string) {
  state.pendingReceipts.delete(federationId);
}

export function federationStateEntries(nowMs = Date.now()): FederationStateEntries {
  prune(nowMs);
  return jsonClone({
    seen: [...state.seen.entries()],
    inbound: [...state.inbound.entries()],
    outbound: [...state.outbound.entries()],
    pendingReceipts: [...state.pendingReceipts.entries()],
  });
}

export function replaceFederationStateEntries(entries: FederationStateEntries) {
  state.seen = new Map(entries.seen.map(([key, value]) => [key, jsonClone(value)]));
  state.inbound = new Map(entries.inbound.map(([key, value]) => [key, jsonClone(value)]));
  state.outbound = new Map(entries.outbound.map(([key, value]) => [key, jsonClone(value)]));
  state.pendingReceipts = new Map(entries.pendingReceipts.map(([key, value]) => [key, jsonClone(value)]));
}
