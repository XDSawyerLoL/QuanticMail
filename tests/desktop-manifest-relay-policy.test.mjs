import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { manifestRelayPolicy } from "../lib/quantic/manifest-relay-policy.mjs";

const external = {
  id: "public",
  label: "Relais public",
  baseUrl: "https://quanticmail-network-relay.onrender.com",
  priority: 10,
  enabled: true,
};

test("Windows signed-manifest authority is only the embedded same-origin relay", () => {
  const policy = manifestRelayPolicy({ desktop: true, configured: [external] });
  assert.equal(policy.relays.length, 1);
  assert.equal(policy.relays[0].id, "quantic-desktop-local");
  assert.equal(policy.relays[0].baseUrl, "");
  assert.deepEqual(policy.retryStatuses, []);
});

test("Windows treats local manifest 404 as not-yet-published rather than retrying Render", () => {
  const policy = manifestRelayPolicy({ desktop: true, configured: [external] });
  const status = 404;
  assert.equal(policy.retryStatuses.includes(status), false);
  assert.equal(policy.relays.some((relay) => relay.baseUrl.includes("onrender.com")), false);
});

test("Windows does not bypass a true 403 on its local relay to publish elsewhere", () => {
  const policy = manifestRelayPolicy({ desktop: true, configured: [external] });
  assert.equal(policy.retryStatuses.includes(403), false);
  assert.deepEqual(policy.relays.map((r) => r.baseUrl), [""]);
});

test("Web client retains configured discovery relays and 404 lookup fallback", () => {
  const policy = manifestRelayPolicy({ desktop: false, configured: [external] });
  assert.equal(policy.relays.length, 2);
  assert.equal(policy.relays[0].baseUrl, "");
  assert.equal(policy.relays[1].baseUrl, external.baseUrl);
  assert.deepEqual(policy.retryStatuses, [404]);
  assert.equal(policy.retryStatuses.includes(403), false);
});

test("Quantic ID authorization remains separate from signed manifest integrity", () => {
  const gate = readFileSync(new URL("../components/quantic-manifest-gate.tsx", import.meta.url), "utf8");
  assert.match(gate, /verifyManifestBrowser\(local\.manifest\)/);
  assert.match(gate, /verifyManifestBrowser\(remote\)/);
  assert.match(gate, /manifestRelayPolicy/);
  assert.match(gate, /DESKTOP_LOCAL_MANIFEST/);
  assert.match(gate, /err\.status === 403/);
  assert.doesNotMatch(gate, /retryStatuses: \[403, 404\]/);
});
