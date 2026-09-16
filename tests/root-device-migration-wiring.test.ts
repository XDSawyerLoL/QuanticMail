import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const routePath = new URL("../app/api/quantic/register/route.ts", import.meta.url);
const clientPath = new URL("../components/quantic-network-v11-app.tsx", import.meta.url);

test("bootstrap register route forwards an explicit legacy root device id", async () => {
  const source = await readFile(routePath, "utf8");
  assert.match(
    source,
    /deviceId:\s*typeof body\.deviceId === "string" \? body\.deviceId : undefined/,
    "the Render/bootstrap register route must forward body.deviceId into registerIdentity",
  );
});

test("V1.2 client sends its persisted root device id during root registration", async () => {
  const source = await readFile(clientPath, "utf8");
  const baseStart = source.indexOf("const base = {");
  assert.notEqual(baseStart, -1, "root registration payload not found");
  const baseEnd = source.indexOf("};", baseStart);
  const registrationPayload = source.slice(baseStart, baseEnd + 2);
  assert.match(
    registrationPayload,
    /deviceId:\s*local\.deviceId/,
    "the client must preserve an existing 10-hex root id after server state loss",
  );
});
