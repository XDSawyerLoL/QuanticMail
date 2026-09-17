export type RelayEndpoint = {
  id: string;
  label: string;
  baseUrl: string;
  priority: number;
  enabled: boolean;
};

export type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;

export const RELAY_STORAGE_KEY = "quantic.relay-endpoints.v1";
export const ACTIVE_RELAY_STORAGE_KEY = "quantic.active-relay.v1";

export const DURABLE_PUBLIC_RELAY: RelayEndpoint = {
  id: "quantic-public",
  label: "Quantic public relay",
  baseUrl: "https://quanticmail-network-relay.onrender.com",
  priority: 10,
  enabled: true,
};

export class RelayHttpError extends Error {
  readonly status: number;
  readonly relay: RelayEndpoint;

  constructor(message: string, status: number, relay: RelayEndpoint) {
    super(message);
    this.status = status;
    this.relay = relay;
  }
}

export class RelayUnavailableError extends Error {
  readonly attempts: { relay: RelayEndpoint; error: unknown }[];

  constructor(attempts: { relay: RelayEndpoint; error: unknown }[]) {
    super("Aucun relais Quantic disponible.");
    this.attempts = attempts;
  }
}

function storageTarget(storage?: StorageLike) {
  return storage ?? (typeof window !== "undefined" ? window.localStorage : undefined);
}

export function normalizeRelayBaseUrl(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "";
  const url = new URL(trimmed);
  if (
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname))
  ) {
    throw new Error("Un relais distant doit utiliser HTTPS (HTTP autorisé uniquement en local).");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("URL de relais invalide.");
  }
  const path = url.pathname.replace(/\/+$/, "");
  return `${url.origin}${path === "/" ? "" : path}`;
}

function sanitizeRelayEndpoint(value: RelayEndpoint, index: number): RelayEndpoint {
  return {
    id: String(value.id || `relay-${index + 1}`),
    label: String(value.label || value.id || `Relais ${index + 1}`),
    baseUrl: normalizeRelayBaseUrl(String(value.baseUrl ?? "")),
    priority: Number.isFinite(value.priority) ? Number(value.priority) : 100 + index,
    enabled: value.enabled !== false,
  };
}

export function parseDefaultRelayEndpoints(value?: string | null): RelayEndpoint[] {
  if (!value?.trim()) return [];
  const unique = new Set<string>();
  const result: RelayEndpoint[] = [];
  for (const candidate of value.split(",")) {
    const baseUrl = normalizeRelayBaseUrl(candidate);
    if (!baseUrl || unique.has(baseUrl)) continue;
    unique.add(baseUrl);
    const index = result.length;
    result.push({
      id: `quantic-seed-${index + 1}`,
      label: `Quantic bootstrap ${index + 1}`,
      baseUrl,
      priority: 20 + index * 10,
      enabled: true,
    });
  }
  return result;
}

export function mergeDefaultRelayEndpoints(
  configured: RelayEndpoint[],
  builtIns: RelayEndpoint[] = [],
): RelayEndpoint[] {
  const seen = new Set<string>();
  const result: RelayEndpoint[] = [];
  for (const [index, input] of [...builtIns, ...configured].entries()) {
    const relay = sanitizeRelayEndpoint(input, index);
    const key = relay.baseUrl || `same-origin:${relay.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(relay);
  }
  return result.sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id));
}

const ENVIRONMENT_BOOTSTRAPS = parseDefaultRelayEndpoints(
  typeof process !== "undefined" ? process.env.NEXT_PUBLIC_QUANTIC_BOOTSTRAPS : undefined,
);

export const DEFAULT_RELAY_ENDPOINTS: RelayEndpoint[] = mergeDefaultRelayEndpoints(
  ENVIRONMENT_BOOTSTRAPS,
  [
    DURABLE_PUBLIC_RELAY,
    {
      id: "quantic-bootstrap",
      label: "Quantic bootstrap",
      baseUrl: "",
      priority: 100,
      enabled: true,
    },
  ],
);

function migrateLegacyBootstrap(relays: RelayEndpoint[]) {
  const hasLegacyBootstrap = relays.some((relay) => relay.id === "quantic-bootstrap");
  const hasDurable = relays.some((relay) => relay.id === DURABLE_PUBLIC_RELAY.id);
  if (!hasLegacyBootstrap || hasDurable) return relays;
  return [{ ...DURABLE_PUBLIC_RELAY }, ...relays];
}

export function orderedRelays(relays: RelayEndpoint[], activeRelayId?: string | null) {
  const ordered = relays
    .map(sanitizeRelayEndpoint)
    .filter((relay) => relay.enabled)
    .sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id));

  if (!activeRelayId) return ordered;
  if (
    activeRelayId === "quantic-bootstrap" &&
    ordered.some((relay) => relay.id === DURABLE_PUBLIC_RELAY.id)
  ) {
    return ordered;
  }
  const activeIndex = ordered.findIndex((relay) => relay.id === activeRelayId);
  if (activeIndex <= 0) return ordered;
  const [active] = ordered.splice(activeIndex, 1);
  ordered.unshift(active);
  return ordered;
}

export function getRelayEndpoints(storage?: StorageLike): RelayEndpoint[] {
  const target = storageTarget(storage);
  if (!target) return DEFAULT_RELAY_ENDPOINTS.map((relay) => ({ ...relay }));
  const raw = target.getItem(RELAY_STORAGE_KEY);
  if (!raw) return DEFAULT_RELAY_ENDPOINTS.map((relay) => ({ ...relay }));
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0) {
      return DEFAULT_RELAY_ENDPOINTS.map((relay) => ({ ...relay }));
    }
    const sanitized = parsed.map((relay, index) => sanitizeRelayEndpoint(relay as RelayEndpoint, index));
    return migrateLegacyBootstrap(sanitized).sort(
      (a, b) => a.priority - b.priority || a.id.localeCompare(b.id),
    );
  } catch {
    return DEFAULT_RELAY_ENDPOINTS.map((relay) => ({ ...relay }));
  }
}

export function saveRelayEndpoints(relays: RelayEndpoint[], storage?: StorageLike) {
  const target = storageTarget(storage);
  if (!target) return;
  const sanitized = relays.map((relay, index) => sanitizeRelayEndpoint(relay, index));
  target.setItem(RELAY_STORAGE_KEY, JSON.stringify(sanitized));
}

export function getActiveRelayId(storage?: StorageLike) {
  const target = storageTarget(storage);
  return target?.getItem(ACTIVE_RELAY_STORAGE_KEY) || null;
}

export function saveActiveRelayId(relayId: string | null, storage?: StorageLike) {
  const target = storageTarget(storage);
  if (!target) return;
  if (!relayId) {
    target.removeItem(ACTIVE_RELAY_STORAGE_KEY);
    return;
  }
  target.setItem(ACTIVE_RELAY_STORAGE_KEY, relayId);
}

export function buildRelayUrl(relay: RelayEndpoint, path: string) {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return relay.baseUrl ? `${normalizeRelayBaseUrl(relay.baseUrl)}${normalizedPath}` : normalizedPath;
}

type RelayFetchOptions = {
  retryStatuses?: number[];
  fetchImpl?: typeof fetch;
  preferredRelayId?: string | null;
};

export function isRetryableRelayStatus(status: number, extra: number[] = []) {
  return status === 408 || status === 425 || status === 429 || status >= 500 || extra.includes(status);
}

export async function relayFetch(
  relays: RelayEndpoint[],
  path: string,
  init?: RequestInit,
  options: RelayFetchOptions = {},
): Promise<{ response: Response; relay: RelayEndpoint }> {
  const candidates = orderedRelays(relays, options.preferredRelayId);
  if (!candidates.length) throw new RelayUnavailableError([]);

  const attempts: { relay: RelayEndpoint; error: unknown }[] = [];
  const fetchImpl = options.fetchImpl ?? fetch;
  const retryStatuses = options.retryStatuses ?? [];
  let lastResponse: { response: Response; relay: RelayEndpoint } | null = null;

  for (const relay of candidates) {
    try {
      const response = await fetchImpl(buildRelayUrl(relay, path), init);
      if (!isRetryableRelayStatus(response.status, retryStatuses)) return { response, relay };
      lastResponse = { response, relay };
      attempts.push({ relay, error: new Error(`HTTP ${response.status}`) });
    } catch (error) {
      attempts.push({ relay, error });
    }
  }

  if (lastResponse) return lastResponse;
  throw new RelayUnavailableError(attempts);
}

export async function relayFetchJson<T>(
  relays: RelayEndpoint[],
  path: string,
  init?: RequestInit,
  options: RelayFetchOptions = {},
): Promise<{ data: T; relay: RelayEndpoint }> {
  const { response, relay } = await relayFetch(relays, path, init, options);
  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) {
    throw new RelayHttpError(data.error ?? `Erreur ${response.status}`, response.status, relay);
  }
  return { data, relay };
}
