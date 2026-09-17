import { getLocalIdentity } from "@/lib/quantic/local-db";
import {
  acknowledgeDirectEnvelopes,
  acknowledgeDirectReceipts,
  listDirectEnvelopes,
  listDirectReceipts,
  startDirectTransport,
  tryDirectSend,
  type DirectSendBody,
} from "@/lib/quantic-network/direct-transport";
import {
  getActiveRelayId,
  getRelayEndpoints,
  isRetryableRelayStatus,
  relayFetch,
  saveActiveRelayId,
} from "@/lib/quantic/relay-client";

const nativeFetch = window.fetch.bind(window);
const DIRECT_RELAY_HEADER = "x-quantic-direct-relay";
startDirectTransport(nativeFetch);

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

function jsonResponse(payload: unknown, status = 200) {
  return new Response(`${JSON.stringify(payload)}\n`, {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function bearerToken(init?: RequestInit) {
  const header = new Headers(init?.headers).get("authorization") ?? "";
  return /^Bearer\s+(.+)$/i.exec(header)?.[1] ?? null;
}

function parseJsonBody(init?: RequestInit) {
  if (typeof init?.body !== "string") return null;
  try {
    const value = JSON.parse(init.body);
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function rewriteJsonBody(init: RequestInit | undefined, body: Record<string, unknown>) {
  return {
    ...init,
    headers: new Headers(init?.headers),
    body: JSON.stringify(body),
  } satisfies RequestInit;
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

async function tryDirectSendRequest(target: URL, init?: RequestInit) {
  if (target.pathname !== "/api/quantic/send" || init?.method?.toUpperCase() !== "POST") return null;
  const body = parseJsonBody(init) as DirectSendBody | null;
  const token = bearerToken(init);
  if (!body || !token) return null;
  const result = await tryDirectSend(body, token);
  if (result.status !== "delivered-direct") return null;
  return jsonResponse({ queued: true, direct: true, envelopeId: result.envelopeId }, 202);
}

async function mergeDirectPull(target: URL, response: Response) {
  if (target.pathname !== "/api/quantic/pull" || !response.ok) return response;
  const handle = (target.searchParams.get("handle") ?? "").trim().toLowerCase();
  const deviceId = (target.searchParams.get("deviceId") ?? "").trim();
  if (!handle || !deviceId) return response;
  const direct = (await listDirectEnvelopes()).filter(
    (envelope) => envelope.to === handle && envelope.toDeviceId === deviceId,
  );
  if (!direct.length) return response;
  const data = await response.clone().json().catch(() => null) as { envelopes?: unknown[] } | null;
  if (!data || !Array.isArray(data.envelopes)) return response;
  const byId = new Map<string, unknown>();
  for (const envelope of [...data.envelopes, ...direct]) {
    const id = (envelope as { id?: unknown })?.id;
    if (typeof id === "string") byId.set(id, envelope);
  }
  return jsonResponse({ ...data, envelopes: [...byId.values()] }, response.status);
}

async function mergeDirectReceipts(target: URL, response: Response) {
  if (target.pathname !== "/api/quantic/receipts" || !response.ok) return response;
  const handle = (target.searchParams.get("handle") ?? "").trim().toLowerCase();
  const deviceId = (target.searchParams.get("deviceId") ?? "").trim();
  if (!handle || !deviceId) return response;
  const direct = (await listDirectReceipts()).filter(
    (receipt) => receipt.to === handle && receipt.toDeviceId === deviceId,
  );
  if (!direct.length) return response;
  const data = await response.clone().json().catch(() => null) as { receipts?: unknown[] } | null;
  if (!data || !Array.isArray(data.receipts)) return response;
  const byId = new Map<string, unknown>();
  for (const receipt of [...data.receipts, ...direct]) {
    const id = (receipt as { id?: unknown })?.id;
    if (typeof id === "string") byId.set(id, receipt);
  }
  return jsonResponse({ ...data, receipts: [...byId.values()] }, response.status);
}

async function stripDirectAcknowledgements(target: URL, init?: RequestInit) {
  if (init?.method?.toUpperCase() !== "POST") return { init, handledOnly: false };
  const body = parseJsonBody(init);
  if (!body || !Array.isArray(body.ids)) return { init, handledOnly: false };
  const ids = body.ids.filter((id): id is string => typeof id === "string");
  if (!ids.length) return { init, handledOnly: false };

  const handled = target.pathname === "/api/quantic/ack"
    ? await acknowledgeDirectEnvelopes(ids)
    : target.pathname === "/api/quantic/receipts"
      ? await acknowledgeDirectReceipts(ids)
      : new Set<string>();
  if (!handled.size) return { init, handledOnly: false };
  const remaining = ids.filter((id) => !handled.has(id));
  if (!remaining.length) return { init, handledOnly: true };
  return {
    init: rewriteJsonBody(init, { ...body, ids: remaining }),
    handledOnly: false,
  };
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

  const directResponse = await tryDirectSendRequest(target, init);
  if (directResponse) return directResponse;

  const stripped = await stripDirectAcknowledgements(target, init);
  if (stripped.handledOnly) return jsonResponse({ acknowledged: true, direct: true });

  const path = `${target.pathname}${target.search}`;
  const retryStatuses = shouldRetryNotFound(path) ? [404] : [];
  const relayInit = await withPersistedRootDeviceId(target, stripped.init);

  const { response, relay } = await relayFetch(getRelayEndpoints(), path, relayInit, {
    fetchImpl: nativeFetch,
    retryStatuses,
    preferredRelayId: getActiveRelayId(),
  });
  if (!isRetryableRelayStatus(response.status, retryStatuses)) {
    saveActiveRelayId(relay.id);
  }
  const withDirectInbox = await mergeDirectPull(target, response);
  return mergeDirectReceipts(target, withDirectInbox);
};
