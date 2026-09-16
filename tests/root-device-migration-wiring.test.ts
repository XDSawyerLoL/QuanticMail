import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const routePath = new URL("../app/api/quantic/register/route.ts", import.meta.url);
const transportPath = new URL("../instrumentation-client.ts", import.meta.url);
const clientPath = new URL("../components/quantic-network-v11-app.tsx", import.meta.url);

test("bootstrap register route forwards an explicit legacy root device id", async () => {
  const source = await readFile(routePath, "utf8");
  assert.match(
    source,
    /deviceId:\s*typeof body\.deviceId === "string" \? body\.deviceId : undefined/,
    "the Render/bootstrap register route must forward body.deviceId into registerIdentity",
  );
});

test("V1.2 transport restores the persisted root device id on root registration", async () => {
  const source = await readFile(transportPath, "utf8");
  assert.match(source, /getLocalIdentity/, "the client transport must read the persisted local identity");
  assert.match(
    source,
    /deviceId:\s*local\.deviceId/,
    "the client transport must preserve an existing 10-hex root id after server state loss",
  );
  assert.match(
    source,
    /target\.pathname\s*!==\s*"\/api\/quantic\/register"/,
    "device-id restoration must be scoped to root registration only",
  );
});

test("root sync adopts the authoritative registered root id before prekeys and pulls", async () => {
  const source = await readFile(clientPath, "utf8");
  assert.match(
    source,
    /const registration = await publishIdentity\(active\)/,
    "sync must keep the registration response instead of discarding it",
  );
  assert.match(
    source,
    /registration\.rootDeviceId[^\n]+active\.deviceId/,
    "sync must compare the registered root id with the local one",
  );
  assert.match(
    source,
    /deviceId:\s*registration\.rootDeviceId/,
    "sync must adopt the server-preserved legacy root id before later operations",
  );
});
