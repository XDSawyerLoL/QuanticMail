import {
  getActiveRelayId,
  getRelayEndpoints,
  relayFetch,
  saveActiveRelayId,
} from "@/lib/quantic/relay-client";

const nativeFetch = window.fetch.bind(window);
const DIRECT_RELAY_HEADER = "x-quantic-direct-relay";

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
  const retryStatuses =
    path.startsWith("/api/quantic/resolve") || path.startsWith("/api/quantic/send") ? [404] : [];

  const { response, relay } = await relayFetch(getRelayEndpoints(), path, init, {
    fetchImpl: nativeFetch,
    retryStatuses,
    preferredRelayId: getActiveRelayId(),
  });
  saveActiveRelayId(relay.id);
  return response;
};
