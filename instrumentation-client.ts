import { getLocalIdentity } from "@/lib/quantic/local-db";
import {
  getActiveRelayId,
  getRelayEndpoints,
  isRetryableRelayStatus,
  relayFetch,
  saveActiveRelayId,
} from "@/lib/quantic/relay-client";

const nativeFetch = window.fetch.bind(window);
const DIRECT_RELAY_HEADER = "x-quantic-direct-relay";

function shouldRetryNotFound(path: string) {
  return (
    path.startsWith("/api/quantic/resolve") ||
    path.startsWith("/api/quantic/send") ||
    path.startsWith("/api/quantic/manifest") ||
    path.startsWith("/api/quantic/devices/revoke") ||
    path.startsWith("/api/quantic/pairing/") ||
    path.startsWith("/api/quantic/registry/status") ||
    path.startsWith("/api/quantic/prekeys/publish") ||
    path.startsWith("/api/quantic/prekeys/status")
  );
}

function samePublicPoint(a: unknown, b: JsonWebKey) {
  if (!a || typeof a !== "object") return false;
  const key = a as JsonWebKey;
  return key.kty === b.kty && key.crv === b.crv && key.x === b.x && key.y === b.y;
}

async function withPersistedRootDeviceId(target: URL, init?: RequestInit) {
  if (
    target.pathname !== "/api/quantic/register" ||
    init?.method?.toUpperCase() !== "POST" ||
    typeof init.body !== "string"
  ) {
    return init;
  }

  try {
    const body = JSON.parse(init.body) as Record<string, unknown>;
    if (typeof body.deviceId === "string" && body.deviceId) return init;
    const local = await getLocalIdentity();
    if (!local?.deviceId || local.role === "secondary" || !samePublicPoint(body.publicKey, local.publicKey)) {
      return init;
    }
    return {
      ...init,
      body: JSON.stringify({ ...body, deviceId: local.deviceId }),
    };
  } catch {
    return init;
  }
}

window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const headers = new Headers(init?.headers);
  if (headers.get(DIRECT_RELAY_HEADER) === "1") {
    headers.delete(DIRECT_RELAY_HEADER);
    return nativeFetch(input, { ...init, headers });
  }

  if (typeof input !== "string" && !(input instanceof URL)) {
    return nativeFetch(input, init);
  }

  const target = new URL(String(input), window.location.origin);
  if (target.origin !== window.location.origin || !target.pathname.startsWith("/api/quantic/")) {
    return nativeFetch(input, init);
  }

  const path = `${target.pathname}${target.search}`;
  const retryStatuses = shouldRetryNotFound(path) ? [404] : [];
  const relayInit = await withPersistedRootDeviceId(target, init);

  const { response, relay } = await relayFetch(getRelayEndpoints(), path, relayInit, {
    fetchImpl: nativeFetch,
    retryStatuses,
    preferredRelayId: getActiveRelayId(),
  });
  if (!isRetryableRelayStatus(response.status, retryStatuses)) {
    saveActiveRelayId(relay.id);
  }
  return response;
};
