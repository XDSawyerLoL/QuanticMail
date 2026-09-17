import type { QuanticRouteManifest } from "./federation-types.ts";
import type { DeliveryReceipt, QuanticPublicKey, RelayEnvelope } from "./relay.ts";
import "./relay.ts";
import {
  exportStandaloneV11State,
  restoreStandaloneV11State,
  type StandaloneV11PersistentState,
} from "./standalone-v11-state.ts";
import {
  replaceRouteManifestEntries,
  routeManifestEntries,
} from "./route-manifest-state.ts";
import {
  federationStateEntries,
  replaceFederationStateEntries,
  type FederationStateEntries,
} from "../../standalone-relay/federation-state.ts";

type IdentityRecord = {
  handle: string;
  address: string;
  canonicalAddress: string;
  fingerprint: string;
  publicKey: QuanticPublicKey;
  signingPublicKey: QuanticPublicKey;
  authTokenHash: string;
  createdAt: string;
  updatedAt: string;
};

type DeviceRecord = {
  canonicalAddress: string;
  deviceId: string;
  label: string;
  publicKey: QuanticPublicKey;
  deviceSigningPublicKey: QuanticPublicKey;
  authTokenHash: string;
  kind: "root" | "linked";
  createdAt: string;
  updatedAt: string;
};

type ChallengeRecord = {
  challenge: string;
  handle: string;
  canonicalAddress: string;
  fingerprint: string;
  publicKey: QuanticPublicKey;
  signingPublicKey: QuanticPublicKey;
  expiresAt: number;
};

type RelayState = {
  identities: Map<string, IdentityRecord>;
  aliases: Map<string, Set<string>>;
  challenges: Map<string, ChallengeRecord>;
  devices: Map<string, DeviceRecord>;
  queues: Map<string, RelayEnvelope[]>;
  receipts: Map<string, DeliveryReceipt[]>;
  sendWindows: Map<string, number[]>;
};

type RelayPersistentStateV1 = {
  format: "quantic-relay-state";
  version: 1;
  savedAt: string;
  identities: Array<[string, IdentityRecord]>;
  aliases: Array<[string, string[]]>;
  challenges: Array<[string, ChallengeRecord]>;
  devices: Array<[string, DeviceRecord]>;
  queues: Array<[string, RelayEnvelope[]]>;
  receipts: Array<[string, DeliveryReceipt[]]>;
  sendWindows: Array<[string, number[]]>;
  routeManifests?: Array<[string, QuanticRouteManifest]>;
  federation?: FederationStateEntries;
};

export type RelayPersistentState = Omit<RelayPersistentStateV1, "version"> &
  StandaloneV11PersistentState & {
    version: 2;
    routeManifests: Array<[string, QuanticRouteManifest]>;
    federation: FederationStateEntries;
  };

const MESSAGE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const SEND_WINDOW_MS = 60_000;

function emptyFederationState(): FederationStateEntries {
  return { seen: [], inbound: [], outbound: [], pendingReceipts: [] };
}

function relayState() {
  const globalRelay = globalThis as typeof globalThis & {
    __quanticRelayState?: RelayState;
  };
  if (!globalRelay.__quanticRelayState) {
    throw new Error("État Quantic Relay non initialisé.");
  }
  return globalRelay.__quanticRelayState;
}

function jsonClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} invalide.`);
  }
  return value as Record<string, unknown>;
}

function requireEntries<T>(value: unknown, label: string): Array<[string, T]> {
  if (!Array.isArray(value)) throw new Error(`${label} doit être un tableau.`);
  const result: Array<[string, T]> = [];
  const keys = new Set<string>();
  for (const entry of value) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string") {
      throw new Error(`${label} contient une entrée invalide.`);
    }
    if (keys.has(entry[0])) throw new Error(`${label} contient une clé dupliquée.`);
    keys.add(entry[0]);
    result.push([entry[0], jsonClone(entry[1] as T)]);
  }
  return result;
}

function requireAliases(value: unknown): Array<[string, string[]]> {
  const entries = requireEntries<unknown>(value, "aliases");
  return entries.map(([key, aliases]) => {
    if (!Array.isArray(aliases) || aliases.some((item) => typeof item !== "string")) {
      throw new Error("aliases contient une valeur invalide.");
    }
    return [key, [...new Set(aliases)]];
  });
}

function requireFederation(value: unknown): FederationStateEntries {
  if (value === undefined) return emptyFederationState();
  const record = requireObject(value, "federation");
  return {
    seen: requireEntries(record.seen, "federation.seen"),
    inbound: requireEntries(record.inbound, "federation.inbound"),
    outbound: requireEntries(record.outbound, "federation.outbound"),
    pendingReceipts: requireEntries(record.pendingReceipts, "federation.pendingReceipts"),
  } as FederationStateEntries;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

export function createEmptyRelayState(savedAt = new Date().toISOString()): RelayPersistentState {
  return {
    format: "quantic-relay-state",
    version: 2,
    savedAt,
    identities: [],
    aliases: [],
    challenges: [],
    devices: [],
    queues: [],
    receipts: [],
    sendWindows: [],
    manifests: [],
    preKeyPools: [],
    consumedPreKeys: [],
    routeManifests: [],
    federation: emptyFederationState(),
  };
}

export function exportRelayState(savedAt = new Date().toISOString()): RelayPersistentState {
  const state = relayState();
  const protocol = exportStandaloneV11State(Date.parse(savedAt));
  return jsonClone({
    format: "quantic-relay-state" as const,
    version: 2 as const,
    savedAt,
    identities: [...state.identities.entries()],
    aliases: [...state.aliases.entries()].map(([key, values]) => [key, [...values]] as [string, string[]]),
    challenges: [...state.challenges.entries()],
    devices: [...state.devices.entries()],
    queues: [...state.queues.entries()],
    receipts: [...state.receipts.entries()],
    sendWindows: [...state.sendWindows.entries()],
    ...protocol,
    routeManifests: routeManifestEntries(),
    federation: federationStateEntries(),
  });
}

export function restoreRelayState(input: unknown, nowMs = Date.now()) {
  const record = requireObject(input, "État Quantic Relay");
  if (record.format !== "quantic-relay-state") throw new Error("Format Quantic Relay inconnu.");
  if (record.version !== 1 && record.version !== 2) throw new Error("Version Quantic Relay inconnue.");
  if (typeof record.savedAt !== "string" || !Number.isFinite(Date.parse(record.savedAt))) {
    throw new Error("savedAt invalide.");
  }

  const identities = requireEntries<IdentityRecord>(record.identities, "identities");
  const aliases = requireAliases(record.aliases);
  const challenges = requireEntries<ChallengeRecord>(record.challenges, "challenges")
    .filter(([, item]) => item && isFiniteNumber(item.expiresAt) && item.expiresAt >= nowMs);
  const devices = requireEntries<DeviceRecord>(record.devices, "devices");
  const cutoff = nowMs - MESSAGE_TTL_MS;
  const queues = requireEntries<RelayEnvelope[]>(record.queues, "queues")
    .map(([key, items]) => {
      if (!Array.isArray(items)) throw new Error("queues contient une valeur invalide.");
      const fresh = items.filter(
        (item) => item && typeof item.createdAt === "string" && Date.parse(item.createdAt) >= cutoff,
      );
      return [key, fresh] as [string, RelayEnvelope[]];
    })
    .filter(([, items]) => items.length > 0);
  const receipts = requireEntries<DeliveryReceipt[]>(record.receipts, "receipts")
    .map(([key, items]) => {
      if (!Array.isArray(items)) throw new Error("receipts contient une valeur invalide.");
      const fresh = items.filter(
        (item) => item && typeof item.deliveredAt === "string" && Date.parse(item.deliveredAt) >= cutoff,
      );
      return [key, fresh] as [string, DeliveryReceipt[]];
    })
    .filter(([, items]) => items.length > 0);
  const sendWindows = requireEntries<number[]>(record.sendWindows, "sendWindows")
    .map(([key, stamps]) => {
      if (!Array.isArray(stamps) || stamps.some((stamp) => !isFiniteNumber(stamp))) {
        throw new Error("sendWindows contient une valeur invalide.");
      }
      return [key, stamps.filter((stamp) => stamp >= nowMs - SEND_WINDOW_MS)] as [string, number[]];
    })
    .filter(([, stamps]) => stamps.length > 0);

  const protocolState: StandaloneV11PersistentState = record.version === 2
    ? {
        manifests: requireEntries(record.manifests, "manifests"),
        preKeyPools: requireEntries(record.preKeyPools, "preKeyPools"),
        consumedPreKeys: requireEntries(record.consumedPreKeys, "consumedPreKeys"),
      } as StandaloneV11PersistentState
    : {
        manifests: [],
        preKeyPools: [],
        consumedPreKeys: [],
      };

  const routeManifests = record.routeManifests === undefined
    ? []
    : requireEntries<QuanticRouteManifest>(record.routeManifests, "routeManifests");
  const federation = requireFederation(record.federation);

  const next: RelayState = {
    identities: new Map(identities),
    aliases: new Map(aliases.map(([key, values]) => [key, new Set(values)])),
    challenges: new Map(challenges),
    devices: new Map(devices),
    queues: new Map(queues),
    receipts: new Map(receipts),
    sendWindows: new Map(sendWindows),
  };

  restoreStandaloneV11State(protocolState, nowMs);

  const state = relayState();
  state.identities = next.identities;
  state.aliases = next.aliases;
  state.challenges = next.challenges;
  state.devices = next.devices;
  state.queues = next.queues;
  state.receipts = next.receipts;
  state.sendWindows = next.sendWindows;
  replaceRouteManifestEntries(routeManifests);
  replaceFederationStateEntries(federation);
  federationStateEntries(nowMs);
}
