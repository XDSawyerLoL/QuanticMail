import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [localDb, device] = await Promise.all([
  readFile(new URL("../lib/quantic/local-db.ts", import.meta.url), "utf8"),
  readFile(new URL("../lib/quantic/device.ts", import.meta.url), "utf8"),
]);

test("local identity and pending-device records can retain private PQ material locally", () => {
  assert.match(localDb, /pqc\?:\s*LocalPqcKeyMaterial/);
  assert.match(localDb, /LocalPqcKeyMaterial/);
});

test("linked device creation stores PQ private material locally and exports only a public proposal", () => {
  assert.match(device, /generateLocalPqcKeyMaterial/);
  assert.match(device, /publicPqcDeviceProposal/);
  assert.match(device, /pqc:\s*pqc\s*\?\?\s*undefined/);
  assert.match(device, /pqc:\s*publicPqc/);
});

test("saving any local identity opportunistically attaches PQ material without UI coupling", () => {
  assert.match(localDb, /generateLocalPqcKeyMaterial/);
  assert.match(localDb, /identity\.pqc\s*\?\?\s*\(await generateLocalPqcKeyMaterial\(\)\)/);
  assert.match(localDb, /pqc:\s*pqc\s*\?\?\s*undefined/);
});
