// Pure routing policy for the signed Quantic identity manifest.
//
// Windows is a local-first app. Its manifest authority for the local mailbox is
// the embedded relay behind the same-origin HTTP proxy. A 404 means that relay
// has not yet received the manifest; looking up a different relay after 404 can
// convert that normal empty-local state into an unrelated 403 ("security sync
// blocked") and can inadvertently publish the signed manifest to that relay.
export function manifestRelayPolicy({ desktop, configured = [] }) {
  const sameOrigin = {
    id: desktop ? "quantic-desktop-local" : "quantic-same-origin",
    label: desktop ? "Relais Quantic local Windows" : "Relais Quantic actuel",
    baseUrl: "",
    priority: 5,
    enabled: true,
  };
  if (desktop) {
    return {
      relays: [sameOrigin],
      // For the local relay, preserve 404 so the caller can distinguish
      // "nothing published yet" from an authorization or signature error.
      retryStatuses: [],
    };
  }
  const seen = new Set(["same-origin"]);
  const relays = [sameOrigin];
  for (const relay of configured) {
    const key = relay.baseUrl || "same-origin";
    if (seen.has(key)) continue;
    seen.add(key);
    relays.push(relay);
  }
  return { relays, retryStatuses: [404] };
}
