import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [localDb, device, app] = await Promise.all([
  readFile(new URL("../lib/quantic/local-db.ts", import.meta.url), "utf8"),
  readFile(new URL("../lib/quantic/device.ts", import.meta.url), "utf8"),
  readFile(new URL("../components/quantic-network-v11-app.tsx", import.meta.url), "utf8"),
]);

test("local identity and pending-device records can retain private PQ material locally", () => {
  assert.match(localDb, /pqc\?:\s*LocalPqcKeyMaterial/);
  assert.match(localDb, /import type \{ LocalPqcKeyMaterial \} from "@\/lib\/quantic\/device-pqc"/);
});

test("linked device creation stores PQ private material locally and exports only a public proposal", () => {
  assert.match(device, /generateLocalPqcKeyMaterial/);
  assert.match(device, /publicPqcDeviceProposal/);
  assert.match(device, /pqc:\s*pqc/);
  assert.match(device, /pqc:\s*publicPqc/);
});

test("root identity creation opportunistically attaches local PQ material", () => {
  assert.match(app, /generateLocalPqcKeyMaterial/);
  assert.match(app, /pqc:\s*pqc\s*\?\?\s*undefined/);
});
