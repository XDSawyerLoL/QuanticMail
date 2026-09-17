import type { QuanticRouteManifest } from "./federation-types.ts";
import type { QuanticIdentityManifest } from "./manifest-types.ts";
import {
  assertVerifiedRouteManifest,
  mergeRouteManifestState,
} from "./route-manifest-node.mjs";

declare global {
  var __quanticRouteManifestState: Map<string, QuanticRouteManifest> | undefined;
}

function state() {
  if (!globalThis.__quanticRouteManifestState) {
    globalThis.__quanticRouteManifestState = new Map<string, QuanticRouteManifest>();
  }
  return globalThis.__quanticRouteManifestState;
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function assertRestorableRoute(key: string, route: QuanticRouteManifest) {
  if (
    !route ||
    route.format !== "quantic-route-manifest" ||
    route.version !== 1 ||
    !route.payload ||
    route.payload.version !== 1 ||
    route.payload.canonicalAddress !== key ||
    !Number.isSafeInteger(route.payload.sequence) ||
    route.payload.sequence < 1
  ) {
    throw new Error("Route Manifest persistant invalide.");
  }
}

export function getRouteManifest(canonicalAddress: string) {
  return state().get(canonicalAddress.trim().toLowerCase()) ?? null;
}

export function acceptRouteManifest(
  manifest: QuanticRouteManifest,
  identityManifest: QuanticIdentityManifest,
  nowMs = Date.now(),
) {
  const verified = assertVerifiedRouteManifest(manifest, identityManifest, nowMs) as QuanticRouteManifest;
  const canonical = verified.payload.canonicalAddress;
  const current = state().get(canonical) ?? null;
  const accepted = mergeRouteManifestState(current, verified) as QuanticRouteManifest;
  state().set(canonical, clone(accepted));
  return accepted;
}

export function routeManifestEntries(): Array<[string, QuanticRouteManifest]> {
  return clone([...state().entries()]);
}

export function replaceRouteManifestEntries(entries: Array<[string, QuanticRouteManifest]>) {
  const next = new Map<string, QuanticRouteManifest>();
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string") {
      throw new Error("Entrée de Route Manifest persistante invalide.");
    }
    const [key, route] = entry;
    const canonical = key.trim().toLowerCase();
    if (next.has(canonical)) throw new Error("Route Manifest persistant dupliqué.");
    assertRestorableRoute(canonical, route);
    next.set(canonical, clone(route));
  }
  globalThis.__quanticRouteManifestState = next;
}
